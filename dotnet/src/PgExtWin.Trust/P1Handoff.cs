using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;
using PgExtWin.Releases;

namespace PgExtWin.Trust;

/// <summary>
/// Independently supplied SHA256 pins: NEVER derive from the signed report,
/// local Catalog, Release API or a bundled key. Authentication of pin origin
/// is an administrative process external to this component.
/// </summary>
public sealed record P1HandoffPins(string PolicySha256, string TrustedRootSha256,
    string P1VerifierSha256, string AuthorityPublicKeySha256);

/// <summary>
/// This represents an authenticated *claim* about P1, not a fresh P1 execution.
/// A signed JSON report alone is never a Sigstore verification result.
/// </summary>
public sealed record P1HandoffAssessment(
    string Scope = "P1_REPORT_AUTHENTICATED_ONLY",
    string VerificationLevel = "UNVERIFIED",
    bool SignatureVerified = false,
    bool PublicationAuthorized = false,
    bool MayInstall = false,
    bool MayBuildRealBundle = false);

public static class P1Handoff
{
    private const int MaxReportBytes = 64 * 1024;
    private const int MaxSignatureBytes = 512;
    private const string Schema = "pgextwin-p1-handoff/v1";
    private const string Decision = "NONPUBLISHING_VALIDATION_ONLY";
    private static readonly Regex Sha = new(@"\A[a-f0-9]{64}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Commit = new(@"\A[a-f0-9]{40}\z", RegexOptions.CultureInvariant);

    // These exact fields are a fixed nonpublishing protocol. No extension
    // field is permitted to smuggle in "publicationAuthorized=true".
    private static readonly HashSet<string> Required = new(StringComparer.Ordinal)
    {
        "schemaVersion", "decision", "catalogCommit", "policySha256",
        "trustedRootSha256", "p1VerifierSha256", "extension", "pgMajor",
        "assetName", "assetSha256", "repositoryId", "releaseId", "assetId",
        "expected", "integrityVerified", "signatureVerified", "blocked",
        "unverified", "complete", "publicationAuthorized", "verifiedAtUtc"
    };

    /// <summary>
    /// Reject unsigned/unpinned/tampered handoffs, replay across assets,
    /// unapproved key substitution and incomplete whole-fleet assertions.
    /// No status elevation is possible through this API.
    /// </summary>
    public static P1HandoffAssessment AuthenticateReport(
        ReadOnlySpan<byte> reportBytes, ReadOnlySpan<byte> detachedSignature,
        string authorityPublicKeyPem, P1HandoffPins independentPins, ReleasePins expectedAsset)
    {
        if (reportBytes.Length is <= 0 or > MaxReportBytes ||
            detachedSignature.Length is <= 0 or > MaxSignatureBytes ||
            string.IsNullOrWhiteSpace(authorityPublicKeyPem) ||
            independentPins is null || expectedAsset is null)
            throw new InvalidDataException("Absent or oversized authenticated handoff input");
        if (!HasSha(independentPins.PolicySha256) || !HasSha(independentPins.TrustedRootSha256) ||
            !HasSha(independentPins.P1VerifierSha256) ||
            !HasSha(independentPins.AuthorityPublicKeySha256))
            throw new InvalidDataException("Missing separately approved immutable trust pins");

        // A public key from the report is NEVER authoritative: verify the
        // independently approved SubjectPublicKeyInfo digest before signature.
        using var key = ECDsa.Create();
        try { key.ImportFromPem(authorityPublicKeyPem); }
        catch (Exception error) when (error is ArgumentException or CryptographicException)
        { throw new InvalidDataException("Unusable authority public key", error); }
        if (!string.Equals(StrictJson.Sha256(key.ExportSubjectPublicKeyInfo()),
                independentPins.AuthorityPublicKeySha256, StringComparison.Ordinal))
            throw new InvalidDataException("Unapproved signature authority key");
        if (key.KeySize != 256 ||
            !key.VerifyData(reportBytes, detachedSignature, HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence))
            throw new InvalidDataException("Detached authenticated P1 report signature failed");

        using var parsed = StrictJson.Parse(reportBytes);
        var obj = parsed.RootElement;
        if (obj.ValueKind != JsonValueKind.Object ||
            !Required.SetEquals(obj.EnumerateObject().Select(p => p.Name)) ||
            !StrictJson.CanonicalBytes(obj).AsSpan().SequenceEqual(reportBytes))
            throw new InvalidDataException("Unexpected/noncanonical signed report");
        string Str(string field)
        {
            var item = obj.GetProperty(field);
            if (item.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("Invalid report field " + field);
            return item.GetString()!;
        }
        long Id(string field)
        {
            var item = obj.GetProperty(field);
            if (item.ValueKind != JsonValueKind.Number || !item.TryGetInt64(out var value) || value <= 0)
                throw new InvalidDataException("Invalid report identifier " + field);
            return value;
        }
        bool Bool(string field)
        {
            var kind = obj.GetProperty(field).ValueKind;
            if (kind is not (JsonValueKind.True or JsonValueKind.False))
                throw new InvalidDataException("Invalid boolean report field " + field);
            return kind == JsonValueKind.True;
        }
        if (!string.Equals(Str("schemaVersion"), Schema, StringComparison.Ordinal) ||
            !string.Equals(Str("decision"), Decision, StringComparison.Ordinal) ||
            !string.Equals(Str("catalogCommit"), expectedAsset.CatalogCommit, StringComparison.Ordinal) ||
            !Commit.IsMatch(expectedAsset.CatalogCommit) ||
            Str("policySha256") != independentPins.PolicySha256 ||
            Str("trustedRootSha256") != independentPins.TrustedRootSha256 ||
            Str("p1VerifierSha256") != independentPins.P1VerifierSha256 ||
            Str("extension") != expectedAsset.Extension ||
            Str("pgMajor") != expectedAsset.PgMajor ||
            Str("assetName") != expectedAsset.AssetName ||
            Str("assetSha256") != expectedAsset.AssetSha256 ||
            !HasSha(expectedAsset.AssetSha256) ||
            Id("repositoryId") != expectedAsset.RepositoryId ||
            Id("releaseId") != expectedAsset.ReleaseId ||
            !expectedAsset.AssetIds.TryGetValue(expectedAsset.AssetName, out var asset) ||
            Id("assetId") != asset)
            throw new InvalidDataException("P1 handoff is substituted, replayed or not independently pinned");

        var expected = Id("expected");
        var matchedIntegrity = Id("integrityVerified");
        var claimedSignature = Id("signatureVerified");
        var blocked = obj.GetProperty("blocked").GetInt64();
        var unverified = obj.GetProperty("unverified").GetInt64();
        if (expected > 10000 || matchedIntegrity != expected ||
            claimedSignature != expected || blocked != 0 || unverified != 0 ||
            !Bool("complete") || Bool("publicationAuthorized"))
            throw new InvalidDataException("P1 signed assertion is incomplete or claims publishing rights");

        if (!DateTimeOffset.TryParseExact(Str("verifiedAtUtc"),
                "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var timestamp) || timestamp.Offset != TimeSpan.Zero)
            throw new InvalidDataException("Invalid signed report UTC timestamp");

        // This is an independently signed *claim* only. We have NOT verified
        // Sigstore certificates, verified original ZIP bytes, run P1, or validated
        // the independently authenticated environment that issued the claim.
        // Never use signed assertion alone as the capability to build bundles.
        return new P1HandoffAssessment();
    }

    private static bool HasSha(string? text) => text is not null && Sha.IsMatch(text);
}
