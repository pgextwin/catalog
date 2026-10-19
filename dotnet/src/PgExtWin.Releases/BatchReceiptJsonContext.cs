using System.Text.Json.Serialization;

namespace PgExtWin.Releases;

// Exact batch-receipt JSON contract. Explicit metadata permits safe trimming
// without making System.Text.Json's reflection-based fallback available.
internal sealed record BatchPackage(
    string Extension, string PgMajor, string ReleaseTag, string CatalogCommit,
    string RelativePath, string Sha256, long Bytes,
    long RepositoryId, long ReleaseId, long AssetId);

internal sealed record BatchDownloadInfo(
    string SchemaVersion, string Source, bool ReleaseMetadataVerified,
    string VerificationLevel, bool SignatureVerified, bool ProvenanceVerified,
    bool PublicationAuthorized, bool DistributionAuthorized,
    bool InstallAuthorized, int ZipCount,
    List<BatchPackage> Packages);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(BatchDownloadInfo))]
internal partial class BatchReceiptJsonContext : JsonSerializerContext
{
}
