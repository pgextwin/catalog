using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;
using Sigstore;

namespace PgExtWin.Releases;

/// <summary>
/// Per-original size and expanded-size bounds derived strictly from the signed
/// OSGeo bundle pin. These limits apply only to the specific pinned bundle and
/// never raise or bypass the global 64 MiB cap used by other original routes.
/// </summary>
public sealed record OsgeoOriginalLimits(long MaxOriginalBytes, long MaxExpandedBytes);

/// <summary>
/// One physical OSGeo PostGIS bundle original keyed by PostgreSQL major.
/// Both PostGIS and pgRouting reference this single admitted original rather
/// than admitting or downloading the same bundle bytes twice.
/// </summary>
public sealed record OsgeoBundleOriginal(
    string BundleId,
    string PgMajor,
    string BundleVersion,
    string FileName,
    long OriginalBytes,
    string OriginalSha256,
    string OriginalProviderUrl,
    OsgeoOriginalLimits Limits,
    IReadOnlyDictionary<string, string> ExtensionVersions);

/// <summary>
/// Signed extension reference mapping an extension name and explicit signed
/// extensionVersion (e.g. postgis 3.7.0, pgrouting 4.0.1) to its shared
/// physical bundle original.
/// </summary>
public sealed record OsgeoExtensionPin(
    string Extension,
    string ExtensionVersion,
    string PgMajor,
    OsgeoBundleOriginal Bundle);

/// <summary>
/// Independently verifiable OSGeo signed admission model. Remains strictly
/// CANDIDATE_ONLY / GET_DENY: carries no public GET, mirror or install authority.
/// </summary>
public sealed record OsgeoSignedAdmissionRecord(
    string SchemaVersion,
    string SourceKind,
    string IssuerRepository,
    string IssuerCommit,
    string CatalogCommit,
    long IssuerRunId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string AdmissionScope,
    string ApprovedOperation,
    bool DownloadAuthorized,
    bool MirrorAuthorized,
    bool RedistributionAuthorized,
    IReadOnlyDictionary<string, OsgeoBundleOriginal> BundlesByMajor,
    IReadOnlyList<OsgeoExtensionPin> Extensions);

/// <summary>
/// Dedicated signed-admission data model and fail-closed validator for OSGeo
/// PostGIS bundle originals (Issue #112). Semantics stay CANDIDATE_ONLY /
/// GET_DENY; this type never performs HTTP requests or enables public GET.
/// </summary>
public static class OsgeoSignedAdmission
{
    private const string SignerSan =
        "https://github.com/pgextwin/build/.github/workflows/external-direct-get-issuer.yml@refs/heads/main";
    private const string SourceRepositoryId = "1405931353";
    private const int MaxMetadataBytes = 2 * 1024 * 1024;
    private const long MaxDerivableOriginalBytes = 1024L * 1024 * 1024;

    // Explicit per-major resource profiles. PG14 (~118.3 MiB) and PG15 (~118.2 MiB)
    // CANNOT share PG18's 96 MiB profile and remain unprofiled (fail-closed) until
    // their actual expanded size and max single-entry size are independently evaluated.
    private static readonly IReadOnlyDictionary<string, OriginalZipResourceProfile> ProfilesByMajor =
        new ReadOnlyDictionary<string, OriginalZipResourceProfile>(
            new Dictionary<string, OriginalZipResourceProfile>(StringComparer.Ordinal)
            {
                ["16"] = ExternalOriginalZipIntegrity.OsgeoPg18Profile,
                ["17"] = ExternalOriginalZipIntegrity.OsgeoPg18Profile,
                ["18"] = ExternalOriginalZipIntegrity.OsgeoPg18Profile
            });

    internal const string ExpectedSchemaVersion = "pgextwin-osgeo-signed-admission/v1";
    internal const string ExpectedSourceKind = "EXTERNAL_OSGEO_POSTGIS_BUNDLE";
    internal const string ExpectedAdmissionScope = "CANDIDATE_ONLY";
    internal const string ExpectedApprovedOperation = "CANDIDATE_ONLY_GET_DENY";
    internal const long ExpandedLimitMultiplier = 24L;

    private static readonly Regex StableVersionRegex = new(
        @"\A(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3}\z",
        RegexOptions.CultureInvariant);
    private static readonly Regex BundleIdRegex = new(
        @"\A[a-z0-9][a-z0-9._-]{2,120}\z",
        RegexOptions.CultureInvariant);
    private static readonly Regex Hex64Regex = new(
        @"\A[0-9a-f]{64}\z",
        RegexOptions.CultureInvariant);
    private static readonly Regex Hex40Regex = new(
        @"\A[0-9a-f]{40}\z",
        RegexOptions.CultureInvariant);

    private static readonly string[] RequiredBundleExtensions = ["postgis", "pgrouting"];

    private static readonly HashSet<string> RootKeys =
    [
        "schemaVersion", "sourceKind", "issuerRepository", "issuerCommit",
        "catalogCommit", "issuerEvent", "issuerRunId", "issuerRunAttempt",
        "ownerActor", "ownerId", "publisherEnvironment", "publisherAppId",
        "admissionScope", "approvedOperation", "issuedAt", "expiresAt",
        "downloadAuthorized", "mirrorAuthorized", "redistributionAuthorized",
        "bundlesByMajor", "extensions"
    ];

    private static readonly HashSet<string> BundleKeys =
    [
        "bundleId", "pgMajor", "bundleVersion", "fileName",
        "originalBytes", "originalSha256", "originalProviderUrl", "limits",
        "targetEnvironment", "licenseUrl", "noticeTreatment",
        "dependencyTreatment", "approvedOperation", "downloadAuthorized",
        "mirrorAuthorized"
    ];

    private static readonly HashSet<string> LimitKeys =
    [
        "maxOriginalBytes", "maxExpandedBytes"
    ];

    private static readonly HashSet<string> ExtensionKeys =
    [
        "extension", "pgMajor", "extensionVersion", "bundleId"
    ];

    // Independently verified OSGeo 3.7.0 bundle originals (PG16/PG17/PG18).
    // The real bundle pgrouting.control declares 4.0.1 (distinct from the
    // upstream description's 4.0.2). Remains CANDIDATE_ONLY / GET_DENY.
    internal static readonly IReadOnlyDictionary<string, OsgeoBundleOriginal> PinnedCandidateBundles =
        CreatePinnedCandidateBundles();

    private static ReadOnlyDictionary<string, OsgeoBundleOriginal> CreatePinnedCandidateBundles()
    {
        var specs = new (string Major, string FileName, long Bytes, string Sha256)[]
        {
            ("16", "postgis-bundle-pg16-3.7.0x64.zip", 84_037_123L,
                "9fd299d661a049833a84584afd2aaea955e189a4d107b9bf579b56ce154d9eb0"),
            ("17", "postgis-bundle-pg17-3.7.0x64.zip", 84_044_726L,
                "eceb7ed45276db6c9f8757e65ccf8d0ceedaebdcd0c401d442371ce8def61450"),
            ("18", "postgis-bundle-pg18-3.7.0x64.zip", 83_739_256L,
                "ac9e9486b3f9161ad86aea948c99b34ca67438f59263f91d2bcb961b51c7a419")
        };
        var map = new Dictionary<string, OsgeoBundleOriginal>(StringComparer.Ordinal);
        foreach (var (major, fileName, bytes, sha256) in specs)
        {
            var versions = new ReadOnlyDictionary<string, string>(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["postgis"] = "3.7.0",
                    ["pgrouting"] = "4.0.1"
                });
            var bundle = new OsgeoBundleOriginal(
                BundleId: $"osgeo-postgis-bundle-pg{major}-3.7.0",
                PgMajor: major,
                BundleVersion: "3.7.0",
                FileName: fileName,
                OriginalBytes: bytes,
                OriginalSha256: sha256,
                OriginalProviderUrl: $"https://download-cache.osgeo.org/postgis/windows/pg{major}/{fileName}",
                Limits: DeriveLimits(bytes),
                ExtensionVersions: versions);
            ValidateBundle(bundle);
            map.Add(major, bundle);
        }
        return new ReadOnlyDictionary<string, OsgeoBundleOriginal>(map);
    }

    private static void Require([System.Diagnostics.CodeAnalysis.DoesNotReturnIf(false)] bool value, string reason)
    {
        if (!value) throw new InvalidDataException("OSGeo signed admission DENY: " + reason);
    }

    private static bool Keys(JsonElement obj, HashSet<string> required) =>
        obj.ValueKind == JsonValueKind.Object &&
        obj.EnumerateObject().Select(x => x.Name).ToHashSet(StringComparer.Ordinal)
            .SetEquals(required);

    private static string RequireString(JsonElement obj, string key)
    {
        var prop = obj.GetProperty(key);
        Require(prop.ValueKind == JsonValueKind.String, $"expected string for '{key}'");
        return prop.GetString() ?? "";
    }

    private static long RequireInt64(JsonElement obj, string key)
    {
        var prop = obj.GetProperty(key);
        long value = 0;
        Require(prop.ValueKind == JsonValueKind.Number && prop.TryGetInt64(out value),
            $"expected integer for '{key}'");
        return value;
    }

    private static DateTimeOffset Timestamp(string raw)
    {
        Require(DateTimeOffset.TryParseExact(raw, "yyyy-MM-ddTHH:mm:ssZ",
            CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal |
                DateTimeStyles.AdjustToUniversal, out var t),
            "invalid timestamp");
        return t;
    }

    private static bool IsSupportedMajor(string? major) =>
        major is "14" or "15" or "16" or "17" or "18";

    /// <summary>
    /// Derive per-original byte and expanded-byte limits strictly from the
    /// pinned original ZIP size rather than lifting any global cap.
    /// </summary>
    internal static OsgeoOriginalLimits DeriveLimits(long originalBytes)
    {
        Require(originalBytes is >= 4 and <= MaxDerivableOriginalBytes,
            "invalid original byte pin for limit derivation");
        return new OsgeoOriginalLimits(
            MaxOriginalBytes: originalBytes,
            MaxExpandedBytes: checked(originalBytes * ExpandedLimitMultiplier));
    }

    internal static void ValidateBundle(OsgeoBundleOriginal? bundle)
    {
        Require(bundle is not null, "missing OSGeo bundle pin");
        Require(bundle!.Limits is not null, "missing per-original limits");
        Require(IsSupportedMajor(bundle.PgMajor), "unsupported or unknown PostgreSQL major");
        Require(BundleIdRegex.IsMatch(bundle.BundleId ?? ""), "invalid bundleId");
        Require(StableVersionRegex.IsMatch(bundle.BundleVersion ?? ""), "invalid bundleVersion");
        var expectedFileName = "postgis-bundle-pg" + bundle.PgMajor + "-" + bundle.BundleVersion + "x64.zip";
        Require(bundle.FileName == expectedFileName &&
            PinnedReleaseSelector.SafeAssetName(bundle.FileName),
            "unexpected OSGeo bundle fileName");
        Require(Hex64Regex.IsMatch(bundle.OriginalSha256 ?? ""), "invalid originalSha256");
        var expectedUrl = "https://download-cache.osgeo.org/postgis/windows/pg" +
            bundle.PgMajor + "/" + bundle.FileName;
        Require(bundle.OriginalProviderUrl == expectedUrl, "unapproved OSGeo originalProviderUrl");
        var expectedLimits = DeriveLimits(bundle.OriginalBytes);
        Require(bundle.Limits == expectedLimits,
            "per-original limits absent or inconsistent with pinned originalBytes");
        Require(bundle.ExtensionVersions is not null &&
            bundle.ExtensionVersions.Count == RequiredBundleExtensions.Length,
            "bundle must declare exact extension versions for postgis and pgrouting");
        foreach (var ext in RequiredBundleExtensions)
        {
            Require(bundle.ExtensionVersions!.TryGetValue(ext, out var ver) &&
                StableVersionRegex.IsMatch(ver ?? ""),
                $"missing or invalid signed extensionVersion for '{ext}'");
        }
        Require(bundle.ExtensionVersions!["postgis"] == bundle.BundleVersion,
            "postgis extensionVersion must match bundleVersion");
    }

    internal static void ValidateAdmission(OsgeoSignedAdmissionRecord? admission)
    {
        Require(admission is not null, "missing OSGeo signed admission record");
        Require(admission!.SchemaVersion == ExpectedSchemaVersion &&
            admission.SourceKind == ExpectedSourceKind &&
            admission.IssuerRepository == "pgextwin/build" &&
            Hex40Regex.IsMatch(admission.IssuerCommit ?? "") &&
            Hex40Regex.IsMatch(admission.CatalogCommit ?? "") &&
            admission.IssuerRunId > 0,
            "invalid admission provenance metadata");
        Require(admission.AdmissionScope == ExpectedAdmissionScope &&
            admission.ApprovedOperation == ExpectedApprovedOperation &&
            !admission.DownloadAuthorized &&
            !admission.MirrorAuthorized &&
            !admission.RedistributionAuthorized,
            "OSGeo admission must remain CANDIDATE_ONLY / GET_DENY");
        Require(admission.ExpiresAt > admission.IssuedAt &&
            admission.ExpiresAt <= admission.IssuedAt.AddDays(30),
            "invalid admission validity window");
        Require(admission.BundlesByMajor is not null &&
            admission.BundlesByMajor.Count is >= 1 and <= 5,
            "empty or oversized bundlesByMajor map");

        var seenBundleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenFileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (majorKey, bundle) in admission.BundlesByMajor!)
        {
            Require(IsSupportedMajor(majorKey) && bundle is not null && bundle.PgMajor == majorKey,
                "bundlesByMajor key mismatch or unknown PG major");
            ValidateBundle(bundle);
            Require(seenBundleIds.Add(bundle!.BundleId) &&
                seenFileNames.Add(bundle.FileName) &&
                seenHashes.Add(bundle.OriginalSha256) &&
                seenUrls.Add(bundle.OriginalProviderUrl),
                "duplicate physical OSGeo bundle admission");
        }

        Require(admission.Extensions is not null &&
            admission.Extensions.Count == admission.BundlesByMajor.Count * RequiredBundleExtensions.Length,
            "extensions list does not match admitted physical bundles");

        var seenExtensions = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in admission.Extensions!)
        {
            Require(item is not null &&
                RequiredBundleExtensions.Contains(item.Extension, StringComparer.Ordinal) &&
                IsSupportedMajor(item.PgMajor) &&
                StableVersionRegex.IsMatch(item.ExtensionVersion ?? ""),
                "invalid extension reference in OSGeo admission");
            Require(seenExtensions.Add(item.PgMajor + "/" + item.Extension),
                "duplicate extension admission for the same PostgreSQL major");
            Require(admission.BundlesByMajor.TryGetValue(item.PgMajor, out var targetBundle) &&
                ReferenceEquals(item.Bundle, targetBundle),
                "extension must reference the single physical bundle original for its major");
            Require(targetBundle.ExtensionVersions.TryGetValue(item.Extension, out var expectedVersion) &&
                item.ExtensionVersion == expectedVersion,
                "extensionVersion differs from bundle's signed extensionVersions");
        }
    }

    // This parser is deliberately *not* an authenticator and never authorizes
    // any HTTP GET. VerifyAsync must validate the Sigstore proof before any
    // consumer may treat the returned record as authentic.
    internal static OsgeoSignedAdmissionRecord ParseUntrusted(
        byte[] bytes, DateTimeOffset now, out string issuerCommit)
    {
        Require(bytes is not null && bytes.Length is > 0 and <= MaxMetadataBytes,
            "missing or oversized OSGeo admission");
        using var doc = StrictJson.Parse(bytes!);
        var root = doc.RootElement;
        Require(Keys(root, RootKeys), "unrecognized OSGeo admission root");

        issuerCommit = RequireString(root, "issuerCommit");
        var schemaVersion = RequireString(root, "schemaVersion");
        var sourceKind = RequireString(root, "sourceKind");
        var issuerRepository = RequireString(root, "issuerRepository");
        var catalogCommit = RequireString(root, "catalogCommit");
        var issuerRunId = RequireInt64(root, "issuerRunId");
        var issuerRunAttempt = RequireInt64(root, "issuerRunAttempt");
        var ownerId = RequireInt64(root, "ownerId");
        var publisherAppId = RequireInt64(root, "publisherAppId");
        var admissionScope = RequireString(root, "admissionScope");
        var approvedOperation = RequireString(root, "approvedOperation");

        Require(schemaVersion == ExpectedSchemaVersion &&
            sourceKind == ExpectedSourceKind &&
            issuerRepository == "pgextwin/build" &&
            Hex40Regex.IsMatch(issuerCommit) &&
            Hex40Regex.IsMatch(catalogCommit) &&
            RequireString(root, "issuerEvent") == "workflow_dispatch" &&
            issuerRunId > 0 &&
            issuerRunAttempt == 1 &&
            RequireString(root, "ownerActor") == "ShutenOishi" &&
            ownerId == 27071164L &&
            RequireString(root, "publisherEnvironment") == "external-direct-provider-publisher" &&
            publisherAppId == 5609317L &&
            admissionScope == ExpectedAdmissionScope &&
            approvedOperation == ExpectedApprovedOperation &&
            root.GetProperty("downloadAuthorized").ValueKind == JsonValueKind.False &&
            root.GetProperty("mirrorAuthorized").ValueKind == JsonValueKind.False &&
            root.GetProperty("redistributionAuthorized").ValueKind == JsonValueKind.False,
            "wrong issuer, event, operation or permission escalation");

        var issued = Timestamp(RequireString(root, "issuedAt"));
        var expires = Timestamp(RequireString(root, "expiresAt"));
        Require(issued <= now.AddMinutes(5) && issued >= now.AddDays(-30) &&
            expires > now && expires > issued && expires <= issued.AddDays(30),
            "expired, future-dated or unbounded admission");

        var bundlesNode = root.GetProperty("bundlesByMajor");
        Require(bundlesNode.ValueKind == JsonValueKind.Object, "bundlesByMajor must be an object");
        var extensionsNode = root.GetProperty("extensions");
        Require(extensionsNode.ValueKind == JsonValueKind.Array, "extensions must be an array");

        // Pre-parse extensions by (pgMajor, extension) so each bundle original
        // carries its explicit signed extensionVersions and shares one physical
        // record across both PostGIS and pgRouting.
        var extensionRows = new List<(string Extension, string PgMajor, string Version, string BundleId)>();
        var extensionVersionsByMajor = new Dictionary<string, Dictionary<string, string>>(StringComparer.Ordinal);
        var seenExtensionPairs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in extensionsNode.EnumerateArray())
        {
            Require(Keys(item, ExtensionKeys), "unrecognized OSGeo extension row");
            var extName = RequireString(item, "extension");
            var major = RequireString(item, "pgMajor");
            var extVersion = RequireString(item, "extensionVersion");
            var bundleId = RequireString(item, "bundleId");
            Require(RequiredBundleExtensions.Contains(extName, StringComparer.Ordinal) &&
                IsSupportedMajor(major) &&
                StableVersionRegex.IsMatch(extVersion) &&
                BundleIdRegex.IsMatch(bundleId),
                "invalid OSGeo extension entry");
            Require(seenExtensionPairs.Add(major + "/" + extName),
                "duplicate OSGeo extension entry for PG major");
            extensionRows.Add((extName, major, extVersion, bundleId));
            if (!extensionVersionsByMajor.TryGetValue(major, out var versionMap))
            {
                versionMap = new Dictionary<string, string>(StringComparer.Ordinal);
                extensionVersionsByMajor.Add(major, versionMap);
            }
            versionMap.Add(extName, extVersion);
        }

        var bundlesByMajor = new Dictionary<string, OsgeoBundleOriginal>(StringComparer.Ordinal);
        foreach (var property in bundlesNode.EnumerateObject())
        {
            var majorKey = property.Name;
            var item = property.Value;
            Require(IsSupportedMajor(majorKey), "unknown PostgreSQL major in bundlesByMajor");
            Require(Keys(item, BundleKeys), "unrecognized OSGeo bundle row");

            var bundleId = RequireString(item, "bundleId");
            var major = RequireString(item, "pgMajor");
            var bundleVersion = RequireString(item, "bundleVersion");
            var fileName = RequireString(item, "fileName");
            var originalBytes = RequireInt64(item, "originalBytes");
            var originalSha256 = RequireString(item, "originalSha256");
            var originalProviderUrl = RequireString(item, "originalProviderUrl");

            Require(major == majorKey, "bundle pgMajor does not match bundlesByMajor key");
            Require(RequireString(item, "approvedOperation") == ExpectedApprovedOperation &&
                item.GetProperty("downloadAuthorized").ValueKind == JsonValueKind.False &&
                item.GetProperty("mirrorAuthorized").ValueKind == JsonValueKind.False,
                "bundle row operation or permission elevation");
            Require(RequireString(item, "targetEnvironment").Contains("PostgreSQL " + major, StringComparison.Ordinal) &&
                RequireString(item, "targetEnvironment").Contains("Windows x64", StringComparison.Ordinal) &&
                RequireString(item, "licenseUrl").StartsWith("https://", StringComparison.Ordinal) &&
                RequireString(item, "noticeTreatment").Length >= 60 &&
                RequireString(item, "dependencyTreatment").Length >= 60,
                "unreviewed rights, ABI scope or PG selection");

            var limitsNode = item.GetProperty("limits");
            Require(Keys(limitsNode, LimitKeys), "missing or unrecognized per-original limits");
            var maxOriginalBytes = RequireInt64(limitsNode, "maxOriginalBytes");
            var maxExpandedBytes = RequireInt64(limitsNode, "maxExpandedBytes");
            var limits = new OsgeoOriginalLimits(maxOriginalBytes, maxExpandedBytes);

            Require(extensionVersionsByMajor.TryGetValue(major, out var extVersions),
                "bundle missing extension version mappings");

            var bundle = new OsgeoBundleOriginal(
                bundleId, major, bundleVersion, fileName,
                originalBytes, originalSha256, originalProviderUrl,
                limits, new ReadOnlyDictionary<string, string>(extVersions));
            ValidateBundle(bundle);
            bundlesByMajor.Add(major, bundle);
        }

        // Confirm every extension row resolves to the exact bundleId of its major.
        var extensionPins = new List<OsgeoExtensionPin>(extensionRows.Count);
        foreach (var (extName, major, extVersion, bundleId) in extensionRows)
        {
            Require(bundlesByMajor.TryGetValue(major, out var bundle),
                "extension references missing PG major bundle pin");
            Require(bundle!.BundleId == bundleId,
                "extension bundleId disagrees with admitted physical bundle");
            extensionPins.Add(new OsgeoExtensionPin(extName, extVersion, major, bundle));
        }

        var record = new OsgeoSignedAdmissionRecord(
            schemaVersion, sourceKind, issuerRepository, issuerCommit, catalogCommit,
            issuerRunId, issued, expires, admissionScope, approvedOperation,
            DownloadAuthorized: false, MirrorAuthorized: false, RedistributionAuthorized: false,
            new ReadOnlyDictionary<string, OsgeoBundleOriginal>(bundlesByMajor),
            extensionPins.AsReadOnly());
        ValidateAdmission(record);
        return record;
    }

    internal static async Task<OsgeoSignedAdmissionRecord> VerifyAsync(
        byte[] admission, byte[] sigstoreBundle, CancellationToken token = default)
    {
        Require(sigstoreBundle is not null && sigstoreBundle.Length is > 0 and <= MaxMetadataBytes,
            "missing or oversized Sigstore bundle");
        var parsedAdmission = ParseUntrusted(admission, DateTimeOffset.UtcNow, out var issuerCommit);

        VerificationResult proof;
        try
        {
            var parsed = SigstoreBundle.Deserialize(Encoding.UTF8.GetString(sigstoreBundle!).Trim());
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
            throw new InvalidDataException("Independent OSGeo admission Sigstore DENY", ex);
        }

        var identity = proof.SignerIdentity;
        var digest = identity?.Extensions?.SourceRepositoryDigest ?? "";
        Require(identity?.SubjectAlternativeName == SignerSan &&
            (digest == issuerCommit || digest == "sha1:" + issuerCommit) &&
            proof.Statement?.PredicateType == "https://slsa.dev/provenance/v1" &&
            proof.VerifiedTimestamps.Count > 0,
            "wrong signed source commit, signer or provenance");
        return parsedAdmission;
    }

    internal static OsgeoBundleOriginal GetBundleForMajor(
        OsgeoSignedAdmissionRecord admission, string pgMajor)
    {
        ValidateAdmission(admission);
        Require(IsSupportedMajor(pgMajor), "unsupported or unknown PostgreSQL major");
        Require(admission.BundlesByMajor.TryGetValue(pgMajor, out var bundle),
            "missing OSGeo bundle pin for PostgreSQL major " + pgMajor);
        return bundle!;
    }

    internal static OsgeoExtensionPin GetExtensionPin(
        OsgeoSignedAdmissionRecord admission, string extension, string pgMajor)
    {
        ValidateAdmission(admission);
        Require(RequiredBundleExtensions.Contains(extension, StringComparer.Ordinal),
            "unknown OSGeo extension");
        Require(IsSupportedMajor(pgMajor), "unsupported or unknown PostgreSQL major");
        var pin = admission.Extensions.FirstOrDefault(
            x => x.Extension == extension && x.PgMajor == pgMajor);
        Require(pin is not null,
            $"missing OSGeo extension pin for {extension} on PostgreSQL {pgMajor}");
        return pin!;
    }

    /// <summary>
    /// Resolve matching physical OSGeo bundle originals with same-bundle
    /// deduplication: selecting both postgis and pgrouting for the same major
    /// returns the single physical original once.
    /// </summary>
    internal static IReadOnlyList<OsgeoBundleOriginal> SelectUniqueOriginals(
        OsgeoSignedAdmissionRecord admission, string pgSelection,
        string? requestedExtension = null, string? requestedVersion = null)
    {
        ValidateAdmission(admission);
        Require(pgSelection == "all" || IsSupportedMajor(pgSelection),
            "unsupported PG selection");
        Require(requestedExtension is null ||
            RequiredBundleExtensions.Contains(requestedExtension, StringComparer.Ordinal),
            "invalid or unsupported requested OSGeo extension");
        Require(requestedVersion is null || (requestedExtension is not null &&
            StableVersionRegex.IsMatch(requestedVersion)),
            "version pin requires an exact stable version and extension");
        if (pgSelection != "all")
        {
            Require(admission.BundlesByMajor.ContainsKey(pgSelection),
                "missing OSGeo bundle pin for PG major " + pgSelection);
        }

        var matched = admission.Extensions
            .Where(pin => pgSelection == "all" || pin.PgMajor == pgSelection)
            .Where(pin => requestedExtension is null || pin.Extension == requestedExtension)
            .Where(pin => requestedVersion is null || pin.ExtensionVersion == requestedVersion)
            .ToList();
        Require(matched.Count > 0,
            "no signed OSGeo original matching exact extension, version and PG major");

        var seenBundleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unique = new List<OsgeoBundleOriginal>();
        foreach (var pin in matched.OrderBy(p => int.Parse(p.PgMajor, CultureInfo.InvariantCulture)))
        {
            if (seenBundleIds.Add(pin.Bundle.BundleId))
                unique.Add(pin.Bundle);
        }
        return unique;
    }

    /// <summary>
    /// Offline, non-authorizing verification of OSGeo bundle ZIP bytes against
    /// the min of the bundle's signed per-original limits (MaxOriginalBytes and
    /// MaxExpandedBytes) and the PG-specific resource profile, plus exact pinned
    /// SHA256. Never lifts the global 64 MiB limit on other routes.
    /// </summary>
    internal static ExternalOriginalZipIntegrity.Receipt VerifyBundleBytes(
        byte[] original, OsgeoBundleOriginal bundle)
    {
        ArgumentNullException.ThrowIfNull(original);
        ValidateBundle(bundle);
        Require(ProfilesByMajor.TryGetValue(bundle.PgMajor, out var profile),
            $"no verified ZIP resource profile for PostgreSQL {bundle.PgMajor}");
        return VerifyBundleBytes(original, bundle, profile!);
    }

    internal static ExternalOriginalZipIntegrity.Receipt VerifyBundleBytes(
        byte[] original, OsgeoBundleOriginal bundle, OriginalZipResourceProfile profile)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(profile);
        ValidateBundle(bundle);
        var limits = bundle.Limits;
        var effectiveProfile = new OriginalZipResourceProfile(
            MaxCompressedOriginalBytes: Math.Min(limits.MaxOriginalBytes, profile.MaxCompressedOriginalBytes),
            MaxEntryUncompressedBytes: Math.Min(limits.MaxExpandedBytes, profile.MaxEntryUncompressedBytes),
            MaxTotalUncompressedBytes: Math.Min(limits.MaxExpandedBytes, profile.MaxTotalUncompressedBytes),
            MaxEntries: profile.MaxEntries);

        return ExternalOriginalZipIntegrity.VerifyWithProfile(
            original,
            bundle.OriginalBytes,
            bundle.OriginalSha256,
            effectiveProfile,
            "CANDIDATE_INTEGRITY_ONLY_NOT_AUTHORIZED");
    }
}
