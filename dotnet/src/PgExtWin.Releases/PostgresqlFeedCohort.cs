using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Catalog;

namespace PgExtWin.Releases;

internal sealed class PostgresqlFeedCohort(string[] required, string? optional)
{
    internal const string OptionalProperty = "optionalPostgresqlMajor";
    internal const int FirstSupportedMajor = 14;
    internal const int HighestPermittedMajor = 32;
    private const int MaxSupportedCohort = 12;

    internal string[] Required { get; } = required;
    internal string? Optional { get; } = optional;
    internal string[] Majors { get; } = optional is null ? required : [.. required, optional];

    internal bool Covers(CatalogEntry entry) =>
        Required.All(major => entry.Versions.Any(version => version.Major == major)) &&
        entry.Versions.All(version => Majors.Contains(version.Major, StringComparer.Ordinal) ||
                                     int.Parse(version.Major) < int.Parse(Required[0]));

    internal static PostgresqlFeedCohort Parse(JsonElement root)
    {
        var raw = root.GetProperty("postgresqlMajors");
        if (raw.ValueKind != JsonValueKind.Array ||
            raw.GetArrayLength() is < 1 or > MaxSupportedCohort)
            throw new InvalidDataException("Invalid signed-feed PG cohort");
        var majors = raw.EnumerateArray().Select(item =>
        {
            if (item.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("Nonstring signed PG major");
            return item.GetString() ?? "";
        }).ToArray();
        if (majors.Any(item => !Regex.IsMatch(item, @"\A[1-9][0-9]*\z")) ||
            majors.Any(item => !int.TryParse(item, out var n) ||
                               n < FirstSupportedMajor || n > HighestPermittedMajor))
            throw new InvalidDataException("Unsupported signed PG major");
        var start = int.Parse(majors[0]);
        if (!majors.SequenceEqual(Enumerable.Range(start, majors.Length)
                                  .Select(n => n.ToString(CultureInfo.InvariantCulture))))
            throw new InvalidDataException("Signed PG cohort has gaps or duplicates");
        if (!root.TryGetProperty(OptionalProperty, out var optional))
            return new(majors, null);
        var next = (start + majors.Length).ToString(CultureInfo.InvariantCulture);
        if (majors.Length == MaxSupportedCohort || start + majors.Length > HighestPermittedMajor ||
            optional.ValueKind != JsonValueKind.String || optional.GetString() != next)
            throw new InvalidDataException("Unsafe optional PostgreSQL major");
        return new(majors, next);
    }
}
