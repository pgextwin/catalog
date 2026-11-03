using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;

namespace PgExtWin.Catalog;

public sealed record ExternalWindowsListing(
    string Extension, string UpstreamVersion, string PgMajor, string Architecture,
    string Provider, string ProviderType, string ReleaseTag, string AssetName,
    string Lifecycle, bool Historical, string VerificationState, bool DownloadAuthorized);

/// <summary>
/// Local, untrusted metadata discovery. NEVER upgrades a raw history entry
/// to a verified ZIP or provides executable download pins.
/// </summary>
public static class WindowsSourceRegistry
{
    public static IReadOnlyList<ExternalWindowsListing> LoadLocal(string catalogDirectory)
    {
        var root = Path.GetFullPath(catalogDirectory);
        // Both files remain local UNVERIFIED discovery metadata, never signed download pins.
        // An absent optional addendum is compatible with earlier catalog snapshots.
        var rows = new List<ExternalWindowsListing>();
        var uniqueIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var name in new[] { "windows-candidates-v1.json", "windows-candidates-portalcorp-v1.json" })
        {
            var path = Path.Combine(root, "external", name);
            if (name != "windows-candidates-v1.json" && !File.Exists(path))
                continue;
            rows.AddRange(LoadOne(path, uniqueIds));
        }
        return rows;
    }

    private static IReadOnlyList<ExternalWindowsListing> LoadOne(
        string path, HashSet<string> uniqueIds)
    {
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < 1 or > 2_000_000 ||
            (file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Local external source inventory is missing, linked, or oversized");
        using var doc = StrictJson.Parse(File.ReadAllBytes(path));
        var obj = doc.RootElement;
        if (Value(obj, "schemaVersion") != "pgextwin-windows-source-candidates/v1" ||
            Value(obj, "trust") != "UNVERIFIED_METADATA_ONLY" ||
            obj.GetProperty("publicationAuthorized").GetBoolean() ||
            obj.GetProperty("redistributionAuthorized").GetBoolean())
            throw new InvalidDataException("External source inventory trust boundary mismatch");
        var values = obj.GetProperty("candidates");
        if (values.ValueKind != JsonValueKind.Array ||
            values.GetArrayLength() is < 1 or > 10000)
            throw new InvalidDataException("Invalid external source candidate count");
        var rows = new List<ExternalWindowsListing>();
        foreach (var item in values.EnumerateArray())
        {
            var name = Value(item, "extension");
            var ver = Value(item, "upstreamVersion");
            var pg = Value(item, "pgMajor");
            var provider = Value(item, "provider");
            var asset = Value(item, "assetName");
            var releaseId = item.GetProperty("releaseId").GetInt64();
            var assetId = item.GetProperty("assetId").GetInt64();
            var sourceRepo = Value(item, "sourceRepo");
            if (!Regex.IsMatch(name, @"\A[a-z][a-z0-9_]*\z") ||
                !Regex.IsMatch(ver, @"\A[0-9]+(?:\.[0-9]+){1,3}\z") ||
                !Regex.IsMatch(pg, @"\A[1-9][0-9]*(?:\.[0-9]+)?\z") ||
                !Regex.IsMatch(asset, @"\A[A-Za-z0-9._+-]+\z") ||
                releaseId <= 0 || assetId <= 0 ||
                !uniqueIds.Add(sourceRepo + ":" + releaseId + ":" + assetId) ||
                Value(item, "sourceGroup") != "external" ||
                Value(item, "buildMethod") != "external" ||
                Value(item, "assetVersion") != ver ||
                Value(item, "verificationState") != "metadata-only" ||
                item.GetProperty("downloadAuthorized").GetBoolean() ||
                item.GetProperty("provenanceVerified").GetBoolean() ||
                item.GetProperty("compatibilityVerified").GetBoolean() ||
                item.GetProperty("rightsReviewed").GetBoolean() ||
                item.GetProperty("dependenciesVerified").GetBoolean() ||
                item.GetProperty("originalSha256").ValueKind != JsonValueKind.Null ||
                Value(item, "redistributionAuthorization") != "not-authorized")
                throw new InvalidDataException("External metadata cannot grant download authority");
            var url = Value(item, "assetUrl");
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps || uri.Host != "github.com" ||
                uri.UserInfo.Length != 0 ||
                !uri.AbsolutePath.StartsWith("/" + sourceRepo + "/releases/download/",
                    StringComparison.Ordinal))
                throw new InvalidDataException("External asset URI does not match source repository");
            rows.Add(new ExternalWindowsListing(
                name, ver, pg, Value(item, "architecture"),
                provider, Value(item, "providerType"), Value(item, "releaseTag"),
                asset, Value(item, "lifecycle"), item.GetProperty("historical").GetBoolean(),
                "UNVERIFIED_METADATA_ONLY", false));
        }
        return rows;
    }

    private static string Value(JsonElement item, string field)
    {
        var el = item.GetProperty(field);
        if (el.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(el.GetString()))
            throw new InvalidDataException("Invalid external metadata: " + field);
        return el.GetString()!;
    }
}
