using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using PgExtWin.Catalog;
using PgExtWin.Core;

namespace PgExtWin.Releases;

/// <summary>
/// Discovers a mutable Catalog head only after GitHub reports a protected main,
/// a verified GitHub web-flow merge signature and a successful exact-head
/// push Validate workflow. This trusts authenticated GitHub API statements:
/// it is NOT independent PGP or extension Sigstore signature verification.
/// The resulting files are fetched from immutable commit URLs, never main.
/// </summary>
public static class AuthenticatedCatalogHead
{
    private static readonly Regex Sha40 = new(@"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Name = new(@"\A[a-z][a-z0-9_]*\z", RegexOptions.CultureInvariant);
    private const int MaxJson = 2 * 1024 * 1024;
    private const string Repository = "pgextwin/catalog";

    public sealed class Session : IDisposable
    {
        public string Commit { get; }
        public string Root { get; }
        public string CatalogPath => Path.Combine(Root, "catalog");
        internal Session(string root, string commit) { Root = root; Commit = commit; }
        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }

    public static async Task<Session> AcquireAsync(string outputParent,
        HttpMessageHandler? handler = null, CancellationToken cancellationToken = default)
    {
        var parent = Path.GetFullPath(outputParent);
        if (!Directory.Exists(parent)) throw new DirectoryNotFoundException("Catalog output parent missing");
        for (DirectoryInfo? item = new(parent); item != null; item = item.Parent)
            if ((item.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Catalog output parent contains a link");

        using var ownedHandler = handler is null ? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None
        } : null;
        using var http = new HttpClient(handler ?? ownedHandler!, disposeHandler: false)
        { Timeout = TimeSpan.FromSeconds(45) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("pgextwin-catalog-head-verifier/1");
        // Optional existing CI/user environment token; never request or persist secrets.
        var token = Environment.GetEnvironmentVariable("GH_TOKEN")
                    ?? Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrWhiteSpace(token))
            http.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        async Task<JsonDocument> ApiAsync(string path)
        {
            var url = new Uri("https://api.github.com/repos/" + Repository + "/" + path);
            return StrictJson.Parse(await ReadAsync(http, url, cancellationToken));
        }

        async Task<string> HeadAsync()
        {
            using var branch = await ApiAsync("branches/main");
            var root = branch.RootElement;
            if (!root.GetProperty("protected").GetBoolean())
                throw new InvalidDataException("Catalog main branch is not protected");
            var sha = root.GetProperty("commit").GetProperty("sha").GetString() ?? "";
            if (!Sha40.IsMatch(sha)) throw new InvalidDataException("Catalog head is not a full commit");
            return sha;
        }

        var commit = await HeadAsync();
        using (var commitDoc = await ApiAsync("commits/" + commit))
        {
            var root = commitDoc.RootElement;
            var signature = root.GetProperty("commit").GetProperty("verification");
            if (root.GetProperty("sha").GetString() != commit ||
                !signature.GetProperty("verified").GetBoolean() ||
                signature.GetProperty("reason").GetString() != "valid" ||
                root.GetProperty("committer").GetProperty("login").GetString() != "web-flow" ||
                root.GetProperty("commit").GetProperty("committer").GetProperty("email").GetString() != "noreply@github.com")
                throw new InvalidDataException("Catalog head is not a verified GitHub signed merge");
        }
        // A branch-head signature by itself is NOT approval. Require the exact
        // successful main-push full Validate workflow, not a PR or older run.
        using (var runs = await ApiAsync("actions/workflows/validate.yml/runs?head_sha=" +
                                        commit + "&event=push&per_page=30"))
        {
            var array = runs.RootElement.GetProperty("workflow_runs");
            if (array.ValueKind != JsonValueKind.Array ||
                !array.EnumerateArray().Any(run =>
                    run.GetProperty("head_sha").GetString() == commit &&
                    run.GetProperty("head_branch").GetString() == "main" &&
                    run.GetProperty("event").GetString() == "push" &&
                    run.GetProperty("status").GetString() == "completed" &&
                    run.GetProperty("conclusion").GetString() == "success" &&
                    run.GetProperty("run_attempt").GetInt32() == 1))
                throw new InvalidDataException("Exact Catalog main push Validate has not succeeded");
        }

        var stage = Path.Combine(parent, ".pgextwin-latest-" + Guid.NewGuid().ToString("N"));
        var session = new Session(stage, commit);
        Directory.CreateDirectory(session.CatalogPath);
        try
        {
            var index = await ReadAsync(http, ImmutableUrl(commit, "index.json"), cancellationToken);
            using var parsed = StrictJson.Parse(index);
            var arr = parsed.RootElement.GetProperty("extensions");
            if (parsed.RootElement.GetProperty("schemaVersion").GetInt32() != 2 ||
                arr.ValueKind != JsonValueKind.Array || arr.GetArrayLength() < VerifiedFleetRoster.MinimumCount ||
                arr.GetArrayLength() > VerifiedFleetRoster.MaximumCount)
                throw new InvalidDataException("Unexpected Catalog v2 fleet");
            var names = arr.EnumerateArray().Select(x => x.GetString() ?? "").ToArray();
            if (names.Any(x => !Name.IsMatch(x)) ||
                !names.SequenceEqual(names.Order(StringComparer.Ordinal)) ||
                names.Distinct(StringComparer.Ordinal).Count() != names.Length)
                throw new InvalidDataException("Unsafe Catalog fleet names");
            VerifiedFleetRoster.Require(names);
            await File.WriteAllBytesAsync(Path.Combine(session.CatalogPath, "index.json"),
                index, cancellationToken);
            var extensionDir = Path.Combine(session.CatalogPath, "extensions");
            Directory.CreateDirectory(extensionDir);
            foreach (var name in names)
            {
                var data = await ReadAsync(http, ImmutableUrl(commit, "extensions/" + name + ".json"),
                    cancellationToken);
                await File.WriteAllBytesAsync(Path.Combine(extensionDir, name + ".json"),
                    data, cancellationToken);
            }
            var entries = CatalogReader.LoadLocal(session.CatalogPath);
            if (entries.Count != names.Length || entries.Any(x => x.Versions.Count != 5))
                throw new InvalidDataException("Catalog latest contains incomplete PG14-18 rows");
            // Fail closed on concurrent publication or head replacement.
            if (await HeadAsync() != commit)
                throw new InvalidDataException("Catalog head changed while downloading");
            return session;
        }
        catch { session.Dispose(); throw; }
    }

    private static Uri ImmutableUrl(string sha, string path) =>
        new("https://raw.githubusercontent.com/pgextwin/catalog/" + sha + "/" + path);

    private static async Task<byte[]> ReadAsync(HttpClient http, Uri url,
        CancellationToken token)
    {
        if (url.Scheme != Uri.UriSchemeHttps || url.Port != 443 ||
            !string.IsNullOrEmpty(url.UserInfo) || !string.IsNullOrEmpty(url.Fragment) ||
            !(url.Host == "api.github.com" &&
              url.AbsolutePath.StartsWith("/repos/pgextwin/catalog/", StringComparison.Ordinal) ||
              url.Host == "raw.githubusercontent.com" &&
              Regex.IsMatch(url.AbsolutePath, @"\A/pgextwin/catalog/[0-9a-f]{40}/(index\.json|extensions/[a-z][a-z0-9_]*\.json)\z")))
            throw new InvalidDataException("Unapproved Catalog HTTPS request");
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException("Catalog authenticated GET HTTP " + (int)response.StatusCode);
        if (response.Content.Headers.ContentLength is long size && (size == 0 || size > MaxJson))
            throw new InvalidDataException("Catalog response exceeds size cap");
        if (response.Content.Headers.ContentType?.MediaType == "text/html")
            throw new InvalidDataException("Catalog received HTML");
        await using var input = await response.Content.ReadAsStreamAsync(token);
        using var output = new MemoryStream();
        var buffer = new byte[81920];
        while (true)
        {
            var n = await input.ReadAsync(buffer.AsMemory(), token);
            if (n == 0) break;
            if (output.Length + n > MaxJson) throw new InvalidDataException("Catalog response too large");
            output.Write(buffer, 0, n);
        }
        if (output.Length == 0) throw new InvalidDataException("Empty Catalog response");
        return output.ToArray();
    }
}
