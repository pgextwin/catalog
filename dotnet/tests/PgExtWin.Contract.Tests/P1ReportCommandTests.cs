using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PgExtWin.Cli;
using PgExtWin.Core;

internal static class P1ReportCommandTests
{
    // A private, synthetic, locally generated signer exercises the real CLI-facing
    // file parser. No GitHub/Sigstore/Release network or production credentials.
    public static void Run(Action<bool, string> check)
    {
        var folder = Path.Combine(Path.GetTempPath(), "pgextwin-r2a-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var catalog = Path.Combine(folder, "catalog");
            Directory.CreateDirectory(Path.Combine(catalog, "extensions"));
            var index = "{\"schemaVersion\":2,\"extensions\":[\"pg_cron\"]}";
            var zipName = "pg_cron-1.0-pg18-windows-x64.zip";
            var assetSha = new string('4', 64);
            var record = JsonSerializer.Serialize(new
            {
                schemaVersion = 2,
                name = "pg_cron",
                displayName = "Synthetic",
                description = "Synthetic-only",
                repository = "pgextwin/pg_cron",
                architecture = "x64",
                latest = new { releaseTag = "synthetic-v1" },
                upstream = new { version = "1.0" },
                postgresql = new Dictionary<string, object> {
                    ["18"] = new { available = true, asset = zipName, sha256 = assetSha }
                },
                runtime = new { requirements = new { preload = "optional" } }
            });
            File.WriteAllText(Path.Combine(catalog, "index.json"), index);
            File.WriteAllText(Path.Combine(catalog, "extensions", "pg_cron.json"), record);

            var rootDigest = new string('2', 64);
            var verifierDigest = new string('3', 64);
            var commit = new string('a', 40);
            var policy = JsonSerializer.Serialize(new
            {
                schemaVersion = "pgextwin-p1-readonly-policy/v1",
                catalogCommitSha = commit,
                signerRepositoryId = 1405931353L,
                rootSha256 = rootDigest,
                catalogDigests = new Dictionary<string, string> {
                    ["index.json"] = StrictJson.Sha256(Encoding.UTF8.GetBytes(index)),
                    ["extensions/pg_cron.json"] = StrictJson.Sha256(Encoding.UTF8.GetBytes(record))
                },
                approvedMajors = new[] { 18 },
                pgEol = new Dictionary<string, string> { ["18"] = "2099-01-01" },
                repoIds = new { pg_cron = 101L },
                releaseIds = new { pg_cron = 202L },
                assetIds = new { pg_cron = new Dictionary<string, long> {
                    [zipName] = 303L, ["SHA256SUMS.txt"] = 304L } }
            });
            var policyPath = Path.Combine(folder, "policy.json");
            File.WriteAllText(policyPath, policy);
            var policyDigest = StrictJson.Sha256(Encoding.UTF8.GetBytes(policy));
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var keyPath = Path.Combine(folder, "authority.pem");
            File.WriteAllText(keyPath, signer.ExportSubjectPublicKeyInfoPem());
            var keyDigest = StrictJson.Sha256(signer.ExportSubjectPublicKeyInfo());

            var claims = new SortedDictionary<string, object>(StringComparer.Ordinal)
            {
                ["schemaVersion"] = "pgextwin-p1-handoff/v1",
                ["decision"] = "NONPUBLISHING_VALIDATION_ONLY",
                ["catalogCommit"] = commit,
                ["policySha256"] = policyDigest,
                ["trustedRootSha256"] = rootDigest,
                ["p1VerifierSha256"] = verifierDigest,
                ["extension"] = "pg_cron",
                ["pgMajor"] = "18",
                ["assetName"] = zipName,
                ["assetSha256"] = assetSha,
                ["repositoryId"] = 101L,
                ["releaseId"] = 202L,
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
            using var doc = StrictJson.Parse(JsonSerializer.SerializeToUtf8Bytes(claims));
            var reportBytes = StrictJson.CanonicalBytes(doc.RootElement);
            var reportPath = Path.Combine(folder, "report.json");
            var signaturePath = Path.Combine(folder, "report.sig");
            File.WriteAllBytes(reportPath, reportBytes);
            File.WriteAllBytes(signaturePath, signer.SignData(reportBytes,
                HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));

            string[] Inputs() => [
                "verify-report", "pg_cron", "--pg", "18", "--catalog-dir", catalog,
                "--policy", policyPath, "--policy-sha256", policyDigest,
                "--trusted-root-sha256", rootDigest, "--p1-verifier-sha256", verifierDigest,
                "--authority-key", keyPath, "--authority-key-sha256", keyDigest,
                "--report", reportPath, "--signature", signaturePath
            ];
            var valid = Inputs();
            check(AuthenticatedReportCommand.Run(valid) == 0,
                "CLI-facing signed P1 report authenticates only its synthetic claim");

            void Reject(string[] args, string reason)
            {
                var denied = false;
                try { AuthenticatedReportCommand.Run(args); }
                catch (Exception e) when (e is ArgumentException or InvalidDataException or
                    JsonException or CryptographicException or KeyNotFoundException)
                { denied = true; }
                check(denied, reason);
            }
            string[] Replaced(string flag, string value)
            {
                var args = Inputs();
                var index = Array.IndexOf(args, flag);
                args[index + 1] = value;
                return args;
            }

            Reject(Replaced("--authority-key-sha256", new string('f', 64)),
                "CLI rejects substituted out-of-band public key SHA");
            Reject(Replaced("--trusted-root-sha256", new string('f', 64)),
                "CLI rejects policy vs independently pinned root mismatch");
            Reject(Replaced("--policy-sha256", new string('f', 64)),
                "CLI rejects changed or attacker-supplied policy pin");
            Reject(Replaced("--pg", "17"), "CLI refuses cross-major replay");
            Reject(Replaced("--report", Path.Combine(folder, "not-found.json")),
                "CLI refuses missing report");
            Reject(Inputs().Concat(["--pg", "18"]).ToArray(),
                "CLI refuses duplicated options");
            Reject(Inputs().Concat(["--publish", "YES"]).ToArray(),
                "CLI refuses privilege-smuggling option");
            var altered = reportBytes.ToArray();
            altered[10] ^= 1;
            File.WriteAllBytes(reportPath, altered);
            Reject(Inputs(), "CLI rejects tampered signed payload");
            File.WriteAllBytes(reportPath, reportBytes);
            File.WriteAllBytes(signaturePath, [1, 2, 3]);
            Reject(Inputs(), "CLI rejects forged signature");
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }
}
