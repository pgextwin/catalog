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

internal sealed record CliExternalSourceRow(
    string Extension, string PgMajor, string UpstreamVersion, string Provider,
    string ProviderType, string ReleaseTag, string AssetName, string Lifecycle,
    bool Historical, string Trust, bool DownloadAuthorized);

internal sealed record CliSourceListEnvelope(
    string SchemaVersion, string Source, string Trust,
    bool CatalogAuthenticated, bool SignatureVerified,
    bool PublicationAuthorized, bool DistributionAuthorized,
    int Count, List<CliCatalogRow> PgextwinRecords,
    List<CliExternalSourceRow> ExternalCandidates);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(CliListEnvelope))]
[JsonSerializable(typeof(CliSourceListEnvelope))]
internal partial class CliJsonContext : JsonSerializerContext
{
}
