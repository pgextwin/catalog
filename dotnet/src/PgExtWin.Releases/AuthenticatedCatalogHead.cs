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
        public IReadOnlyList<string> ApprovedMajors { get; }
        public string Root { get; }
        public string CatalogPath => Path.Combine(Root, "catalog");
        internal Session(string root, string commit, IReadOnlyList<string> majors)
        { Root = root; Commit = commit; ApprovedMajors = majors; }
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
        var cohortBytes = await ReadAsync(http, ImmutableUrl(commit, "config/cli-feed-majors.json"),
            cancellationToken);
        var cohort = ParseCohort(cohortBytes);
        var session = new Session(stage, commit, cohort.Required);
        Directory.CreateDirectory(session.CatalogPath);
        try
        {
            Directory.CreateDirectory(Path.Combine(session.CatalogPath, "config"));
            await File.WriteAllBytesAsync(
                Path.Combine(session.CatalogPath, "config", "cli-feed-majors.json"),
                cohortBytes, cancellationToken);
            var index = await ReadAsync(http, ImmutableUrl(commit, "index.json"),
                cancellationToken);
            var names = ParseV3Fleet(index);
            var identitiesDir = Path.Combine(session.CatalogPath, "identities");
            var packagesDir = Path.Combine(session.CatalogPath, "packages");
            Directory.CreateDirectory(identitiesDir);
            Directory.CreateDirectory(packagesDir);
            await File.WriteAllBytesAsync(Path.Combine(session.CatalogPath, "index.json"),
                index, cancellationToken);
            foreach (var name in names)
            {
                var identity = await ReadAsync(http, ImmutableUrl(commit, "identities/" + name + ".json"),
                    cancellationToken);
                ValidateDistributedIdentity(identity, name);
                await File.WriteAllBytesAsync(Path.Combine(identitiesDir, name + ".json"),
                    identity, cancellationToken);
                var ledger = await ReadAsync(http, ImmutableUrl(commit, "packages/" + name + ".json"),
                    cancellationToken);
                await File.WriteAllBytesAsync(Path.Combine(packagesDir, name + ".json"),
                    ledger, cancellationToken);
            }
            var entries = CatalogReader.LoadLocal(session.CatalogPath);
            if (entries.Count != names.Length || entries.Any(entry => !cohort.Covers(entry)))
                throw new InvalidDataException("Catalog latest missing approved cohort");
            // Fail closed on concurrent publication or head replacement.
            if (await HeadAsync() != commit)
                throw new InvalidDataException("Catalog head changed while downloading");
            return session;
        }
        catch { session.Dispose(); throw; }
    }

    private static string[] ParseV3Fleet(byte[] indexPayload)
    {
        using var parsed = StrictJson.Parse(indexPayload);
        var root = parsed.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("schemaVersion", out var schema) ||
            schema.ValueKind != JsonValueKind.Number || !schema.TryGetInt32(out var version) || version != 3 ||
            !root.TryGetProperty("identitiesDir", out var idDir) || idDir.GetString() != "identities" ||
            !root.TryGetProperty("packagesDir", out var pkgDir) || pkgDir.GetString() != "packages" ||
            !root.TryGetProperty("extensions", out var arr) ||
            arr.ValueKind != JsonValueKind.Array || arr.GetArrayLength() < VerifiedFleetRoster.MinimumCount ||
            arr.GetArrayLength() > VerifiedFleetRoster.MaximumCount ||
            !root.TryGetProperty("identities", out var identities) ||
            identities.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Unexpected Catalog v3 fleet");

        var names = new string[arr.GetArrayLength()];
        var index = 0;
        foreach (var item in arr.EnumerateArray())
        {
            var value = item.ValueKind == JsonValueKind.String ? item.GetString() ?? "" : "";
            if (!Name.IsMatch(value))
                throw new InvalidDataException("Unsafe Catalog fleet names");
            names[index++] = value;
        }
        if (!names.SequenceEqual(names.Order(StringComparer.Ordinal)) ||
            names.Distinct(StringComparer.Ordinal).Count() != names.Length)
            throw new InvalidDataException("Unsafe Catalog fleet names");
        VerifiedFleetRoster.Require(names);

        var seenIdentities = new HashSet<string>(StringComparer.Ordinal);
        var distributedIdentities = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in identities.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object ||
                !item.TryGetProperty("name", out var n) || n.ValueKind != JsonValueKind.String ||
                !item.TryGetProperty("path", out var p) || p.ValueKind != JsonValueKind.String ||
                !item.TryGetProperty("intakeClass", out var c) || c.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("Unexpected Catalog v3 identity entry");
            var entryName = n.GetString() ?? "";
            var intakeClass = c.GetString() ?? "";
            if (!Name.IsMatch(entryName) || !seenIdentities.Add(entryName) ||
                p.GetString() != "identities/" + entryName + ".json")
                throw new InvalidDataException("Unsafe Catalog v3 identity entry");
            if (intakeClass == "distributed")
            {
                if (!item.TryGetProperty("ledgerPath", out var l) || l.ValueKind != JsonValueKind.String ||
                    l.GetString() != "packages/" + entryName + ".json")
                    throw new InvalidDataException("Invalid distributed ledgerPath in Catalog v3 index");
                distributedIdentities.Add(entryName);
            }
            else if (intakeClass == "research-only")
            {
                if (item.TryGetProperty("ledgerPath", out _))
                    throw new InvalidDataException("Unexpected ledgerPath for research-only identity");
            }
            else
            {
                throw new InvalidDataException("Unexpected Catalog v3 intakeClass");
            }
        }
        if (!distributedIdentities.Order(StringComparer.Ordinal).SequenceEqual(names))
            throw new InvalidDataException("Catalog v3 identity roster mismatch");
        return names;
    }

    private static void ValidateDistributedIdentity(byte[] payload, string expectedName)
    {
        using var doc = StrictJson.Parse(payload);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("schemaVersion", out var schema) ||
            schema.ValueKind != JsonValueKind.Number || !schema.TryGetInt32(out var version) || version != 1 ||
            !root.TryGetProperty("name", out var name) || name.GetString() != expectedName ||
            !root.TryGetProperty("intake", out var intake) || intake.ValueKind != JsonValueKind.Object ||
            !intake.TryGetProperty("class", out var intakeClass) || intakeClass.GetString() != "distributed" ||
            !intake.TryGetProperty("distributionAllowed", out var allowed) ||
            allowed.ValueKind != JsonValueKind.True ||
            !root.TryGetProperty("distribution", out var dist) || dist.ValueKind != JsonValueKind.Object ||
            !dist.TryGetProperty("repository", out var repo) || repo.GetString() != "pgextwin/" + expectedName ||
            !dist.TryGetProperty("ledgerPath", out var ledger) || ledger.GetString() != "packages/" + expectedName + ".json")
            throw new InvalidDataException("Invalid or unauthorized Catalog identity: " + expectedName);
    }

    private static PostgresqlFeedCohort ParseCohort(byte[] payload)
    {
        // Protected-main cohort, authenticated with the signed merge and
        // exact-head Validate. This is NOT independent Sigstore feed validation.
        using var doc = StrictJson.Parse(payload);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            root.EnumerateObject().Count() !=
                (root.TryGetProperty(PostgresqlFeedCohort.OptionalProperty, out _) ? 3 : 2) ||
            root.GetProperty("schemaVersion").GetInt32() != 1)
            throw new InvalidDataException("Invalid protected Catalog PG cohort policy");
        return PostgresqlFeedCohort.Parse(root);
    }

    private static Uri ImmutableUrl(string sha, string path) =>
        new("https://raw.githubusercontent.com/pgextwin/catalog/" + sha + "/" + path);

    internal static bool IsApprovedCatalogUri(Uri url) =>
        url.Scheme == Uri.UriSchemeHttps && url.Port == 443 &&
        string.IsNullOrEmpty(url.UserInfo) && string.IsNullOrEmpty(url.Fragment) &&
        (url.Host == "api.github.com" &&
         url.AbsolutePath.StartsWith("/repos/pgextwin/catalog/", StringComparison.Ordinal) ||
         url.Host == "raw.githubusercontent.com" &&
         Regex.IsMatch(url.AbsolutePath,
             @"\A/pgextwin/catalog/[0-9a-f]{40}/(config/cli-feed-majors\.json|index\.json|(?:identities|packages)/[a-z][a-z0-9_]*\.json)\z",
             RegexOptions.CultureInvariant));

    private static async Task<byte[]> ReadAsync(HttpClient http, Uri url,
        CancellationToken token)
    {
        if (!IsApprovedCatalogUri(url))
            throw new InvalidDataException("Unapproved Catalog HTTPS request");
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Accept.ParseAdd("application/vnd.github+json");
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            // Never log the request's Authorization header or response body.
            // Public, allowlisted endpoint and rate-limit headers distinguish
            // anonymous REST exhaustion from a denied immutable raw URL.
            static string Header(HttpResponseMessage r, string key) =>
                r.Headers.TryGetValues(key, out var values) ?
                values.FirstOrDefault() ?? "absent" : "absent";
            var kind = url.Host == "api.github.com" ? "GITHUB_API" : "IMMUTABLE_RAW";
            throw new HttpRequestException("Catalog authenticated GET HTTP " +
                (int)response.StatusCode + " TARGET=" + kind +
                " PATH=" + url.AbsolutePath +
                " RATE_REMAINING=" + Header(response, "X-RateLimit-Remaining") +
                " RATE_RESET=" + Header(response, "X-RateLimit-Reset") +
                " RETRY_AFTER=" + Header(response, "Retry-After"));
        }
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
