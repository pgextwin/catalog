using System.Globalization;
using System.Text;
using System.Text.Json;
using Sigstore;
using PgExtWin.Core;

namespace PgExtWin.Releases;

/// <summary>
/// External original-provider GET permission requires a separately issued,
/// independently Sigstore-verified, source-specific Build Publisher admission.
/// No local JSON, existing deny-only pin, unsigned review or Catalog discovery
/// can authorize this path. The issuer workflow identity is pinned in code.
/// </summary>
public static class ExternalSignedDirectGetAdmission
{
    private const string SignerSan =
        "https://github.com/pgextwin/build/.github/workflows/external-direct-get-issuer.yml@refs/heads/main";
    private const string SourceRepositoryId = "1405931353";
    private const int MaxBytes = 2 * 1024 * 1024;
    private static readonly HashSet<string> RootKeys =
    [
        "schemaVersion", "sourceKind", "issuerRepository", "issuerCommit",
        "catalogCommit", "issuerEvent", "issuerRunId", "issuerRunAttempt",
        "ownerActor", "ownerId", "publisherEnvironment", "publisherAppId",
        "approvedOperation", "issuedAt", "expiresAt", "downloadAuthorized",
        "mirrorAuthorized", "redistributionAuthorized", "records"
    ];
    private static readonly HashSet<string> RecordKeys =
    [
        "sourceGroup", "extension", "pgMajor", "targetEnvironment",
        "sourceRepo", "repositoryId", "releaseTag", "releaseId",
        "assetName", "assetId", "originalBytes", "originalSha256",
        "originalProviderUrl", "licenseUrl", "noticeTreatment",
        "dependencyTreatment", "approvedOperation", "downloadAuthorized",
        "mirrorAuthorized"
    ];

    private static void Require(bool value, string reason)
    {
        if (!value) throw new InvalidDataException("External signed admission DENY: " + reason);
    }

    private static bool Keys(JsonElement obj, HashSet<string> required) =>
        obj.ValueKind == JsonValueKind.Object &&
        obj.EnumerateObject().Select(x => x.Name).ToHashSet(StringComparer.Ordinal)
            .SetEquals(required);

    private static bool Hex(string? s, int n) =>
        s is not null && s.Length == n && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static DateTimeOffset Timestamp(string raw)
    {
        Require(DateTimeOffset.TryParseExact(raw, "yyyy-MM-ddTHH:mm:ssZ",
            CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal |
                DateTimeStyles.AdjustToUniversal, out var t),
            "invalid timestamp");
        return t;
    }

    // This parser is deliberately *not* an authenticator. No caller may invoke
    // a transport using its return value before VerifyAsync authenticates the
    // actual exact bytes and the independently pinned GitHub OIDC signer.
    internal static IReadOnlyList<ExternalOriginalPin> ParseUntrusted(
        byte[] bytes, string pgSelection, DateTimeOffset now, out string issuerCommit)
    {
        Require(bytes.Length is > 0 and <= MaxBytes, "oversized admission");
        Require(pgSelection is "14" or "15" or "16" or "17" or "18" or "all",
            "unsupported PG selection");
        using var doc = StrictJson.Parse(bytes);
        var root = doc.RootElement;
        Require(Keys(root, RootKeys), "unrecognized admission root");
        string Str(string key) => root.GetProperty(key).GetString() ?? "";
        issuerCommit = Str("issuerCommit");
        Require(Str("schemaVersion") == "pgextwin-external-direct-get-admission/v1" &&
            Str("sourceKind") == "EXTERNAL_GITHUB_RELEASE_ASSET" &&
            Str("issuerRepository") == "pgextwin/build" &&
            Hex(issuerCommit, 40) && Hex(Str("catalogCommit"), 40) &&
            Str("issuerEvent") == "workflow_dispatch" &&
            root.GetProperty("issuerRunId").GetInt64() > 0 &&
            root.GetProperty("issuerRunAttempt").GetInt32() == 1 &&
            Str("ownerActor") == "ShutenOishi" &&
            root.GetProperty("ownerId").GetInt64() == 27071164 &&
            Str("publisherEnvironment") == "external-direct-provider-publisher" &&
            root.GetProperty("publisherAppId").GetInt64() == 5609317 &&
            Str("approvedOperation") == "ORIGINAL_PROVIDER_GET_ONLY" &&
            root.GetProperty("downloadAuthorized").ValueKind == JsonValueKind.True &&
            root.GetProperty("mirrorAuthorized").ValueKind == JsonValueKind.False &&
            root.GetProperty("redistributionAuthorized").ValueKind == JsonValueKind.False,
            "wrong issuer, event, operation or permission");
        var issued = Timestamp(Str("issuedAt"));
        var expires = Timestamp(Str("expiresAt"));
        Require(issued <= now.AddMinutes(5) && issued >= now.AddDays(-30) &&
            expires > now && expires > issued && expires <= issued.AddDays(30),
            "expired, future-dated or unbounded admission");

        var entries = root.GetProperty("records");
        Require(entries.ValueKind == JsonValueKind.Array &&
            entries.GetArrayLength() is >= 1 and <= 20, "empty or oversized signed cohort");
        var sourceIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var destinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<ExternalOriginalPin>();
        foreach (var item in entries.EnumerateArray())
        {
            Require(Keys(item, RecordKeys), "unrecognized signed source row");
            string Value(string key) => item.GetProperty(key).GetString() ?? "";
            var major = Value("pgMajor");
            var repo = Value("sourceRepo");
            Require(Value("sourceGroup") == "external" &&
                Value("approvedOperation") == "ORIGINAL_PROVIDER_GET_ONLY" &&
                item.GetProperty("downloadAuthorized").ValueKind == JsonValueKind.True &&
                item.GetProperty("mirrorAuthorized").ValueKind == JsonValueKind.False,
                "row operation elevation");
            // Existing initial-two P3 hold remains a separate hard boundary.
            Require(repo is not ("laurenz/oracle_fdw" or "andreiramani/pgvector_pgsql_windows"),
                "held initial two cannot be admitted through this new source kind");
            // Validate EVERY signed row even when the caller requests one PG major.
            // Filtering before full validation could conceal an unauthorized row.
            Require(Value("targetEnvironment").Contains("PostgreSQL " + major, StringComparison.Ordinal) &&
                Value("targetEnvironment").Contains("Windows x64", StringComparison.Ordinal) &&
                Value("licenseUrl").StartsWith("https://", StringComparison.Ordinal) &&
                Value("noticeTreatment").Length >= 60 &&
                Value("dependencyTreatment").Length >= 60,
                "unreviewed rights, ABI scope or PG selection");
            var pin = new ExternalOriginalPin(Value("extension"), major, repo,
                item.GetProperty("repositoryId").GetInt64(), Value("releaseTag"),
                item.GetProperty("releaseId").GetInt64(), Value("assetName"),
                item.GetProperty("assetId").GetInt64(), item.GetProperty("originalBytes").GetInt64(),
                Value("originalSha256"), Value("originalProviderUrl"));
            ExternalProviderAssetTransport.ValidatePin(pin);
            Require(sourceIds.Add(repo + ":" + pin.ReleaseId + ":" + pin.AssetId) &&
                destinations.Add("pg" + major + "/" + pin.Extension + "/" + pin.AssetName),
                "replayed, duplicate or colliding signed asset");
            result.Add(pin);
        }
        var selected = pgSelection == "all"
            ? result
            : result.Where(pin => pin.PgMajor == pgSelection).ToList();
        Require(selected.Count > 0, "no independently signed asset for requested PG major");
        return selected;
    }

    internal static async Task<IReadOnlyList<ExternalOriginalPin>> VerifyAsync(
        byte[] admission, byte[] bundle, string pgSelection,
        CancellationToken token = default)
    {
        Require(bundle.Length is > 0 and <= MaxBytes, "missing or oversized Sigstore bundle");
        var pins = ParseUntrusted(admission, pgSelection, DateTimeOffset.UtcNow,
            out var issuerCommit);

        VerificationResult proof;
        try
        {
            var parsed = SigstoreBundle.Deserialize(Encoding.UTF8.GetString(bundle).Trim());
            var verifier = new SigstoreVerifier();
            proof = await verifier.VerifyAsync(admission, parsed, new VerificationPolicy
            {
                RequireTransparencyLog = true,
                CertificateIdentity = new CertificateIdentity
                {
                    SubjectAlternativeName = SignerSan,
                    Issuer = "https://token.actions.githubusercontent.com",
                    Extensions = new CertificateExtensionPolicy
                    {
                        SourceRepositoryUri = "https://github.com/pgextwin/build",
                        SourceRepositoryRef = "refs/heads/main",
                        SourceRepositoryIdentifier = SourceRepositoryId,
                        RunnerEnvironment = "github-hosted"
                    }
                }
            }, token);
        }
        catch (Exception ex) when (ex is VerificationException or JsonException or
            FormatException or InvalidOperationException or HttpRequestException or IOException)
        {
            throw new InvalidDataException("Independent external admission Sigstore DENY", ex);
        }
        var identity = proof.SignerIdentity;
        var digest = identity?.Extensions?.SourceRepositoryDigest ?? "";
        Require(identity?.SubjectAlternativeName == SignerSan &&
            (digest == issuerCommit || digest == "sha1:" + issuerCommit) &&
            proof.Statement?.PredicateType == "https://slsa.dev/provenance/v1" &&
            proof.VerifiedTimestamps.Count > 0,
            "wrong signed source commit, signer or provenance");
        return pins;
    }
    /// <summary>
    /// Only user-local GET of original bytes, after independent signed admission.
    /// No upload, mirror, repackage, install or fallback is possible here.
    /// </summary>
    public static async Task<BatchReleaseDownloader.BatchResult> StageVerifiedAsync(
        string admissionFile, string bundleFile, string pgSelection,
        string outputParent, CancellationToken token = default)
    {
        static byte[] ReadSmallFile(string path)
        {
            var file = new FileInfo(path);
            if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
                file.Length is <= 0 or > MaxBytes)
                throw new InvalidDataException("Missing, linked or oversized external admission proof");
            return File.ReadAllBytes(file.FullName);
        }

        var admission = ReadSmallFile(admissionFile);
        var bundle = ReadSmallFile(bundleFile);
        var pins = await VerifyAsync(admission, bundle, pgSelection, token);
        // This expiry comes from the same exact bytes independently verified
        // against the original Build issuer's Sigstore proof above.
        using var signed = StrictJson.Parse(admission);
        var expires = Timestamp(signed.RootElement.GetProperty("expiresAt").GetString() ?? "");
        Task ConfirmFresh(CancellationToken cancellation)
        {
            cancellation.ThrowIfCancellationRequested();
            Require(DateTimeOffset.UtcNow < expires,
                "admission expired before provider GET or atomic commit");
            return Task.CompletedTask;
        }
        using var transport = new ExternalProviderAssetTransport();
        return await ExternalOriginalBatchStager.StageAsync(
            pins, pgSelection, outputParent,
            (pin, directory, cancellation) => transport.DownloadAsync(
                pin, directory, cancellation), token, ConfirmFresh);
    }

}
