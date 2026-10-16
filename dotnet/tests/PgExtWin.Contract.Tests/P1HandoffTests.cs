using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PgExtWin.Core;
using PgExtWin.Releases;
using PgExtWin.Trust;

/// <summary>No real private key, trusted root, Sigstore, GitHub or network is used.
/// Generated ECDSA key exists only for fake in-memory hostile fixtures.</summary>
internal static class P1HandoffTests
{
    public static void Run(Action<bool, string> check)
    {
        var fakePolicy = new string('1', 64);
        var fakeRoot = new string('2', 64);
        var fakeVerifier = new string('3', 64);
        var assetHash = new string('4', 64);
        var pins = new ReleasePins("pg_cron", "18", "fake-v1", "pg_cron-1.0-pg18-windows-x64.zip",
            assetHash, 101, 202, new Dictionary<string,long> { ["pg_cron-1.0-pg18-windows-x64.zip"] = 303 },
            new string('a',40));

        using var privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = privateKey.ExportSubjectPublicKeyInfoPem();
        var publicHash = StrictJson.Sha256(privateKey.ExportSubjectPublicKeyInfo());
        var trusted = new P1HandoffPins(fakePolicy, fakeRoot, fakeVerifier, publicHash);

        SortedDictionary<string, object> Claims() => new(StringComparer.Ordinal)
        {
            ["schemaVersion"] = "pgextwin-p1-handoff/v1",
            ["decision"] = "NONPUBLISHING_VALIDATION_ONLY",
            ["catalogCommit"] = pins.CatalogCommit,
            ["policySha256"] = fakePolicy,
            ["trustedRootSha256"] = fakeRoot,
            ["p1VerifierSha256"] = fakeVerifier,
            ["extension"] = pins.Extension,
            ["pgMajor"] = pins.PgMajor,
            ["assetName"] = pins.AssetName,
            ["assetSha256"] = pins.AssetSha256,
            ["repositoryId"] = pins.RepositoryId,
            ["releaseId"] = pins.ReleaseId,
            ["assetId"] = 303L,
            ["expected"] = 70L,
            ["integrityVerified"] = 70L,
            ["signatureVerified"] = 70L,
            ["blocked"] = 0L,
            ["unverified"] = 0L,
            ["complete"] = true,
            ["publicationAuthorized"] = false,
            ["verifiedAtUtc"] = "2026-10-16T06:00:00Z"
        };
        byte[] Canonical(SortedDictionary<string,object> values)
        {
            using var json = StrictJson.Parse(JsonSerializer.SerializeToUtf8Bytes(values));
            return StrictJson.CanonicalBytes(json.RootElement);
        }
        byte[] Sign(byte[] payload) => privateKey.SignData(payload,
            HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var report = Canonical(Claims());
        var signature = Sign(report);
        var result = P1Handoff.AuthenticateReport(report, signature, pem, trusted, pins);
        check(result.Scope == "P1_REPORT_AUTHENTICATED_ONLY" &&
            result.VerificationLevel == "UNVERIFIED" &&
            !result.SignatureVerified && !result.PublicationAuthorized &&
            !result.MayInstall && !result.MayBuildRealBundle,
            "Even an authenticated synthetic P1 assertion NEVER self-grants Sigstore or distribution");

        void Reject(Action action, string reason)
        {
            bool denied = false;
            try { action(); }
            catch (Exception e) when (e is InvalidDataException or JsonException)
            { denied = true; }
            check(denied, reason);
        }
        void RejectChanged(string field, object replacement, string reason)
        {
            var fields = Claims();
            fields[field] = replacement;
            var b = Canonical(fields);
            Reject(() => P1Handoff.AuthenticateReport(b, Sign(b), pem, trusted, pins), reason);
        }
        Reject(() => P1Handoff.AuthenticateReport(report, [], pem, trusted, pins),
            "No signature is not authorization");
        Reject(() => P1Handoff.AuthenticateReport(report, new byte[] { 1,2,3 }, pem, trusted, pins),
            "Forged detached signature rejected");
        var tampered = report.ToArray();
        tampered[^3] ^= 1;
        Reject(() => P1Handoff.AuthenticateReport(tampered, signature, pem, trusted, pins),
            "Changed signed JSON byte rejected");
        Reject(() => P1Handoff.AuthenticateReport(report, signature, pem,
            trusted with { AuthorityPublicKeySha256 = new string('f', 64) }, pins),
            "Unapproved authority key digest rejected");
        using (var impostor = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            Reject(() => P1Handoff.AuthenticateReport(report, signature,
                impostor.ExportSubjectPublicKeyInfoPem(), trusted, pins),
                "New attacker authority key rejected");
        Reject(() => P1Handoff.AuthenticateReport(report, signature, pem,
            trusted with { PolicySha256 = new string('f',64) }, pins),
            "Out-of-band policy pin mismatch");
        Reject(() => P1Handoff.AuthenticateReport(report, signature, pem,
            trusted with { TrustedRootSha256 = new string('f',64) }, pins),
            "Independently approved trusted root mismatch");
        Reject(() => P1Handoff.AuthenticateReport(report, signature, pem,
            trusted with { P1VerifierSha256 = new string('f',64) }, pins),
            "P1 verifier hash mismatch");
        Reject(() => P1Handoff.AuthenticateReport(report, signature, pem, trusted,
            pins with { PgMajor = "17" }), "PG17/18 replay rejected");
        Reject(() => P1Handoff.AuthenticateReport(report, signature, pem, trusted,
            pins with { ReleaseId = 203 }), "Changed Release ID rejected");
        Reject(() => P1Handoff.AuthenticateReport(report, signature, pem, trusted,
            pins with { AssetSha256 = new string('5', 64) }), "Changed original ZIP digest rejected");
        RejectChanged("assetId", 304L, "Changed Asset ID rejected");
        RejectChanged("repositoryId", 102L, "Different numeric repository ID rejected");
        RejectChanged("blocked", 1L, "Incomplete P1 fleet denied");
        RejectChanged("signatureVerified", 69L, "One unsigned P1 row denied");
        RejectChanged("publicationAuthorized", true, "Signed report cannot authorize publication");
        RejectChanged("complete", false, "Incomplete P1 report denied");
        RejectChanged("decision", "PUBLICATION_GO", "Unapproved decision denied");
        RejectChanged("verifiedAtUtc", "not-utc", "Invalid UTC clock format denied");
        RejectChanged("expected", 0L, "Empty success fleet denied");
        RejectChanged("expected", 10001L, "Unbounded P1 result count denied");
        var extra = Claims();
        extra["sigstoreVerified"] = true;
        var extraBytes = Canonical(extra);
        Reject(() => P1Handoff.AuthenticateReport(extraBytes, Sign(extraBytes), pem, trusted, pins),
            "Unknown self-asserted trust field denied");
        var duplicated = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(report)
            .Replace("\"complete\":true", "\"complete\":false,\"complete\":true", StringComparison.Ordinal));
        Reject(() => P1Handoff.AuthenticateReport(duplicated, Sign(duplicated), pem, trusted, pins),
            "Duplicate JSON key denied despite valid ECDSA");
        var notCanonical = report[..^1];
        Reject(() => P1Handoff.AuthenticateReport(notCanonical, Sign(notCanonical), pem, trusted, pins),
            "Signed noncanonical report denied");
    }
}
