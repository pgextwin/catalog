using System.Text.Json.Serialization;

namespace PgExtWin.Cli;

// Explicit System.Text.Json metadata is trim-safe and preserves the exact
// v0.3.x listing response (including false authenticity/authorization flags).
internal sealed record CliCatalogRow(
    string Extension, string PgMajor, string UpstreamVersion,
    string ReleaseTag, string AssetName, string Preload, string Trust);

internal sealed record CliListEnvelope(
    string SchemaVersion, string Source, string Trust,
    bool CatalogAuthenticated, bool SignatureVerified,
    bool PublicationAuthorized, bool DistributionAuthorized,
    int Count, List<CliCatalogRow> Records);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(CliListEnvelope))]
internal partial class CliJsonContext : JsonSerializerContext
{
}
