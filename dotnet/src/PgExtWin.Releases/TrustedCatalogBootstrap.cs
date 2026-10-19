using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Catalog;
using PgExtWin.Core;

namespace PgExtWin.Releases;

/// <summary>
/// Strict offline-verifiable bootstrap for the CLI's *fixed* historical P1
/// candidate policy and immutable Catalog snapshot. The independently baked
/// SHA256 below must not be obtained from the same HTTP response as the policy.
/// It proves source integrity against this CLI's pinned build, NOT original
/// extension Sigstore authenticity nor historical P1 formal acceptance.
/// </summary>
public static class TrustedCatalogBootstrap
{
    // These constants are updated only by reviewed source/CI and a new signed CLI.
    public const string PolicySourceCommit =
        "4dcf3b9c601c6fd43a7ee34bb0f73592f5509a34";
    public const string PolicySha256 =
        "dc1e52bbb10f52d0c1f14913e99bf30e6dc4855e0c39d0547b78f39da549f201";
    public const string CatalogSnapshotCommit =
        "e372e2c6a95adcf8227ea82d6253df3792b6f029";
    public const string PolicyPath = "config/issue112-p1-fleet-pins-20261017.json";
    private const int Limit = 2 * 1024 * 1024;
    private static readonly Regex SafeFile =
        new(@"\Aextensions/[a-z][a-z0-9_]*\.json\z",
            RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public sealed class Session : IDisposable
    {
        public string Root { get; }
        public string CatalogPath => Path.Combine(Root, "catalog");
        public string PolicyFile => Path.Combine(Root, "candidate-policy.json");
        internal Session(string root) => Root = root;
        public void Dispose()
        {
            if (Directory.Exists(Root))
                Directory.Delete(Root, recursive: true);
        }
    }

    public static async Task<Session> AcquireAsync(string outputParent,
        HttpMessageHandler? httpHandler = null,
        CancellationToken cancellationToken = default, Action<string>? progress = null)
    {
        var root = Path.GetFullPath(outputParent);
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException("Output parent must exist");
        for (DirectoryInfo? p = new(root); p is not null; p = p.Parent)
            if ((p.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Output parent contains a filesystem link");

        using var handler = httpHandler is null ? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        } : null;
        using var client = httpHandler is null
            ? new HttpClient(handler!, disposeHandler: false)
            : new HttpClient(httpHandler, disposeHandler: false);
        client.Timeout = TimeSpan.FromSeconds(45);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-cli-pinned-bootstrap/1.0");

        var stage = Path.Combine(root, ".pgextwin-bootstrap-" + Guid.NewGuid().ToString("N"));
        var session = new Session(stage);
        Directory.CreateDirectory(session.CatalogPath);
        try
        {
            progress?.Invoke("FIXED_POLICY_FETCH_START trust=PINNED_SHA256");
            var policyUri = PinnedUrl(PolicySourceCommit, PolicyPath);
            var policy = await FetchBoundedAsync(client, policyUri, cancellationToken);
            if (StrictJson.Sha256(policy) != PolicySha256)
                throw new InvalidDataException("Embedded approved P1 policy SHA256 mismatch");
            progress?.Invoke($"FIXED_POLICY_SHA256_VERIFIED bytes={policy.Length}");
            using var parsed = StrictJson.Parse(policy);
            var document = parsed.RootElement;
            if (document.GetProperty("schemaVersion").GetString() !=
                    "pgextwin-p1-readonly-policy/v1" ||
                document.GetProperty("catalogCommitSha").GetString() != CatalogSnapshotCommit)
                throw new InvalidDataException("Embedded P1 policy Catalog commit mismatch");
            var digests = document.GetProperty("catalogDigests");
            var entries = digests.EnumerateObject().ToArray();
            if (entries.Length != 15 ||
                !digests.TryGetProperty("index.json", out _))
                throw new InvalidDataException("Embedded P1 Catalog inventory incomplete");
            foreach (var entry in entries)
            {
                var path = entry.Name;
                if (path != "index.json" && !SafeFile.IsMatch(path))
                    throw new InvalidDataException("Catalog contains unsafe or unknown path");
                var expected = entry.Value.GetString() ?? "";
                if (!Regex.IsMatch(expected, @"\A[0-9a-f]{64}\z",
                        RegexOptions.CultureInvariant))
                    throw new InvalidDataException("Catalog has invalid SHA256 pin");
                var data = await FetchBoundedAsync(client,
                    PinnedUrl(CatalogSnapshotCommit, path), cancellationToken);
                if (StrictJson.Sha256(data) != expected)
                    throw new InvalidDataException("Immutable Catalog original bytes changed");
                var file = Path.Combine(session.CatalogPath,
                    path.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(file)!);
                await File.WriteAllBytesAsync(file, data, cancellationToken);
                progress?.Invoke($"FIXED_CATALOG_RECORD_VERIFIED path={path} bytes={data.Length}");
            }
            await File.WriteAllBytesAsync(session.PolicyFile, policy, cancellationToken);
            var records = CatalogReader.LoadLocal(session.CatalogPath);
            if (records.Count != 14 || records.Any(x => x.Versions.Count != 5))
                throw new InvalidDataException("Pinned Catalog is not the 14x5 fleet");
            // Reuse existing strict P1 selector, including every Catalog digest,
            // approved PG majors, Release and numeric asset identity inventory.
            _ = PinnedReleaseSelector.FromLocalFiles(
                session.CatalogPath, session.PolicyFile, PolicySha256,
                records[0].Name, "18");
            progress?.Invoke("FIXED_CATALOG_READY zip_count=70 trust=INTEGRITY_ONLY");
            return session;
        }
        catch
        {
            session.Dispose();
            throw;
        }
    }

    private static Uri PinnedUrl(string commit, string path) =>
        new("https://raw.githubusercontent.com/pgextwin/catalog/" + commit + "/" + path);

    private static async Task<byte[]> FetchBoundedAsync(HttpClient http, Uri url,
        CancellationToken cancellationToken)
    {
        if (url.Scheme != Uri.UriSchemeHttps ||
            url.Host != "raw.githubusercontent.com" || url.Port != 443 ||
            !url.AbsolutePath.StartsWith("/pgextwin/catalog/", StringComparison.Ordinal))
            throw new InvalidDataException("Bootstrap endpoint is not immutable GitHub HTTPS");
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/octet-stream");
        using var response = await http.SendAsync(request,
            HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException("Pinned bootstrap GET failed: " +
                (int)response.StatusCode);
        if (response.Content.Headers.ContentLength is long length &&
            (length <= 0 || length > Limit))
            throw new InvalidDataException("Pinned bootstrap payload size invalid");
        var media = response.Content.Headers.ContentType?.MediaType;
        if (media == "text/html")
            throw new InvalidDataException("Pinned bootstrap returned HTML");
        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        while (true)
        {
            var n = await input.ReadAsync(buffer, cancellationToken);
            if (n == 0) break;
            if (output.Length + n > Limit)
                throw new InvalidDataException("Bootstrap payload exceeded 2MiB limit");
            output.Write(buffer, 0, n);
        }
        if (output.Length == 0) throw new InvalidDataException("Empty pinned bootstrap file");
        return output.ToArray();
    }
}
