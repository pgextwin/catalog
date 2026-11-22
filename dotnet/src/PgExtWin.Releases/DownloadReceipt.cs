namespace PgExtWin.Releases;

/// <summary>SHA-256 byte match only: never signature-verified, never publishing authorization.</summary>
public sealed record DownloadReceipt(string FilePath, string Sha256, long Size,
    long RepositoryId, long ReleaseId, long AssetId, string VerificationLevel = "INTEGRITY_ONLY");
