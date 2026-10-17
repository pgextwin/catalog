using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Core;
using PgExtWin.Releases;
using PgExtWin.Trust;

namespace PgExtWin.Cli;

/// <summary>
/// Offline authentication of a separately issued P1 report claim. This never
/// validates an original Sigstore attestation, Release bytes or distribution rights.
/// </summary>
public static class AuthenticatedReportCommand
{
    private static readonly HashSet<string> RequiredOptions = new(StringComparer.Ordinal)
    {
        "--catalog-dir", "--pg", "--policy", "--policy-sha256",
        "--report", "--signature", "--authority-key", "--authority-key-sha256",
        "--trusted-root-sha256", "--p1-verifier-sha256"
    };

    public static int Run(string[] args)
    {
        if (args.Length < 2 || args[0] != "verify-report")
            throw new ArgumentException("verify-report requires one extension name and pinned inputs");

        var extension = args[1];
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        if ((args.Length - 2) % 2 != 0)
            throw new ArgumentException("Missing verify-report option value");
        for (var i = 2; i < args.Length; i += 2)
        {
            var key = args[i];
            if (!RequiredOptions.Contains(key) || !options.TryAdd(key, args[i + 1]) ||
                string.IsNullOrWhiteSpace(args[i + 1]))
                throw new ArgumentException("Unexpected, empty or repeated verify-report option: " + key);
        }
        if (options.Count != RequiredOptions.Count)
            throw new ArgumentException("Missing mandatory verify-report pin/file option");

        var policyDigest = options["--policy-sha256"];
        var rootDigest = options["--trusted-root-sha256"];
        var verifierDigest = options["--p1-verifier-sha256"];
        var keyDigest = options["--authority-key-sha256"];
        foreach (var value in new[] { policyDigest, rootDigest, verifierDigest, keyDigest })
            if (!Regex.IsMatch(value, @"\A[0-9a-f]{64}\z", RegexOptions.CultureInvariant))
                throw new InvalidDataException("Trust pins must be independent lowercase SHA256 hex digests");

        // Check the independently pinned Catalog and entire policy inventory first.
        var release = PinnedReleaseSelector.FromLocalFiles(
            options["--catalog-dir"], options["--policy"], policyDigest,
            extension, options["--pg"]);

        // Both the approved independent root digest and the pinned policy's
        // recorded root must agree. This does not verify actual Trusted Root bytes.
        using (var policy = StrictJson.Parse(ReadBoundedFile(options["--policy"], 2 * 1024 * 1024)))
        {
            if (policy.RootElement.GetProperty("rootSha256").GetString() != rootDigest)
                throw new InvalidDataException("Pinned policy Trusted Root differs from independent root pin");
        }

        var reportBytes = ReadBoundedFile(options["--report"], 64 * 1024);
        var signatureBytes = ReadBoundedFile(options["--signature"], 512);
        var keyPem = new UTF8Encoding(false, true).GetString(
            ReadBoundedFile(options["--authority-key"], 8192));

        var result = P1Handoff.AuthenticateReport(reportBytes, signatureBytes, keyPem,
            new P1HandoffPins(policyDigest, rootDigest, verifierDigest, keyDigest), release);
        if (result.Scope != "P1_REPORT_AUTHENTICATED_ONLY" ||
            result.VerificationLevel != "UNVERIFIED" || result.SignatureVerified ||
            result.PublicationAuthorized || result.MayBuildRealBundle || result.MayInstall)
            throw new InvalidDataException("Unexpected privilege in authenticated report assessment");

        Console.WriteLine("REPORT_SIGNATURE_AUTHENTICATED=true P1_REPORT_AUTHENTICATED_ONLY " +
            "TRUST=UNVERIFIED SIGSTORE_SIGNATURE_VERIFIED=false ORIGINAL_BYTES_VERIFIED=false " +
            "PUBLISH=DENY DISTRIBUTION=DENY INSTALL=DENY");
        Console.WriteLine($"EXTENSION={release.Extension} PG={release.PgMajor} " +
            $"REPOSITORY_ID={release.RepositoryId} RELEASE_ID={release.ReleaseId}");
        return 0;
    }

    private static byte[] ReadBoundedFile(string path, int limit)
    {
        var file = new FileInfo(path);
        if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
            file.Length <= 0 || file.Length > limit)
            throw new InvalidDataException("Missing, linked, empty or oversized report trust input");
        using var input = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length != file.Length)
            throw new InvalidDataException("Report input changed while opening");
        var data = new byte[(int)input.Length];
        input.ReadExactly(data);
        if (input.ReadByte() != -1)
            throw new InvalidDataException("Report input changed while reading");
        return data;
    }
}
