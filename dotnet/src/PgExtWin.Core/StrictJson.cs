using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace PgExtWin.Core;

/// <summary>
/// Read-only subset of the existing Python P0 canonical contract.
/// Does not validate signatures, provenance, authorization or JSON Schema.
/// </summary>
public static class StrictJson
{
    public static JsonDocument Parse(ReadOnlySpan<byte> utf8)
    {
        var document = JsonDocument.Parse(utf8.ToArray(), new JsonDocumentOptions
        {
            AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 64
        });
        try
        {
            CheckDuplicateKeys(document.RootElement);
            return document;
        }
        catch
        {
            document.Dispose();
            throw;
        }
    }

    private static void CheckDuplicateKeys(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in node.EnumerateObject())
            {
                if (!seen.Add(property.Name))
                    throw new InvalidDataException($"Duplicate JSON key: {property.Name}");
                CheckDuplicateKeys(property.Value);
            }
        }
        else if (node.ValueKind == JsonValueKind.Array)
        {
            foreach (var child in node.EnumerateArray()) CheckDuplicateKeys(child);
        }
    }

    public static byte[] CanonicalBytes(JsonElement element, string? omitTopLevelKey = null)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Indented = false,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            SkipValidation = false
        }))
        {
            CanonicalWrite(writer, element, omitTopLevelKey);
            writer.Flush();
        }
        stream.WriteByte((byte)'\n'); // Python P0 canonical() appends exactly one LF.
        return stream.ToArray();
    }

    public static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void CanonicalWrite(Utf8JsonWriter writer, JsonElement node, string? omitKey = null)
    {
        switch (node.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var p in node.EnumerateObject().OrderBy(p => p.Name, PythonKeyComparer.Instance))
                {
                    if (p.Name == omitKey) continue;
                    writer.WritePropertyName(p.Name);
                    CanonicalWrite(writer, p.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var child in node.EnumerateArray()) CanonicalWrite(writer, child);
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                writer.WriteStringValue(node.GetString());
                break;
            case JsonValueKind.Number:
                // P0 manifests use integers. Do not silently canonicalize JSON floats differently from Python.
                var text = node.GetRawText();
                if (!System.Text.RegularExpressions.Regex.IsMatch(text, @"\A(?:0|-?[1-9][0-9]*)\z") ||
                    !long.TryParse(text, System.Globalization.NumberStyles.Integer,
                        System.Globalization.CultureInfo.InvariantCulture, out var number))
                    throw new InvalidDataException("Non-integer/out-of-range JSON number is not canonicalized");
                writer.WriteNumberValue(number);
                break;
            case JsonValueKind.True: writer.WriteBooleanValue(true); break;
            case JsonValueKind.False: writer.WriteBooleanValue(false); break;
            case JsonValueKind.Null: writer.WriteNullValue(); break;
            default: throw new InvalidDataException("Unsupported JSON node");
        }
    }

    // Python sort_keys uses Unicode scalar values, rather than UTF-16 ordinal code units.
    private sealed class PythonKeyComparer : IComparer<string>
    {
        public static readonly PythonKeyComparer Instance = new();
        public int Compare(string? x, string? y)
        {
            if (x is null) return y is null ? 0 : -1;
            if (y is null) return 1;
            var a = x.EnumerateRunes().GetEnumerator();
            var b = y.EnumerateRunes().GetEnumerator();
            while (true)
            {
                var am = a.MoveNext(); var bm = b.MoveNext();
                if (!am || !bm) return am == bm ? 0 : am ? 1 : -1;
                var c = a.Current.Value.CompareTo(b.Current.Value);
                if (c != 0) return c;
            }
        }
    }
}

public static class ManifestV1
{
    /// <summary>Check only P0 envelope and deterministic hash, NEVER signature truth.</summary>
    public static void CheckStructuralEnvelope(ReadOnlySpan<byte> bytes)
    {
        using var document = StrictJson.Parse(bytes);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("schemaVersion", out var schema) ||
            schema.GetString() != "pgextwin-distribution-manifest/v1" ||
            !root.TryGetProperty("publicationAuthorized", out var publish) ||
            publish.ValueKind != JsonValueKind.False ||
            !root.TryGetProperty("trust", out var trust) || trust.ValueKind != JsonValueKind.Object ||
            !trust.TryGetProperty("offlineTrustRoot", out var anchor) ||
            anchor.GetString() != "EXTERNAL_REQUIRED" ||
            !trust.TryGetProperty("outerArchiveSigned", out var signed) ||
            signed.ValueKind != JsonValueKind.False ||
            !root.TryGetProperty("snapshotId", out var digest) ||
            digest.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("Not a nonpublishing P0 Manifest v1 envelope");
        var expected = StrictJson.Sha256(StrictJson.CanonicalBytes(root, "snapshotId"));
        if (!string.Equals(digest.GetString(), expected, StringComparison.Ordinal))
            throw new InvalidDataException("Manifest snapshotId mismatch");
    }
}
