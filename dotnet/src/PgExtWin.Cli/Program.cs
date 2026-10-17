using System.Reflection;
using System.Text.Json;
using System.Net;
using PgExtWin.Catalog;
using PgExtWin.Releases;

return await RunAsync(args);

static async Task<int> RunAsync(string[] args)
{
    try
    {
        if (args.Length == 1 && args[0] is "--version" or "-V")
        {
            var info = Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            Console.WriteLine(info?.Split('+')[0] ?? "UNVERSIONED");
            return 0;
        }
        if (args.Length == 1 && args[0] is "--help" or "-h" or "help")
        {
            Usage(); return 0;
        }
        if (args.Length < 1 || args[0] is not ("list" or "search" or "download"))
            throw new ArgumentException("Only list/search and explicit GET-only download are available");
        var command = args[0];
        var i = 1;
        string? query = null;
        if (command is "search" or "download")
        {
            if (i >= args.Length || args[i].StartsWith('-'))
                throw new ArgumentException(command + " requires an extension name/search term");
            query = args[i++];
        }
        string? directory = null;
        string? pg = null;
        string? policy = null;
        string? policySha = null;
        string? output = null;
        string? format = null;
        while (i < args.Length)
        {
            if (i + 1 >= args.Length) throw new ArgumentException("Missing option value");
            var option = args[i++]; var value = args[i++];
            switch (option)
            {
                case "--catalog-dir":
                    if (directory is not null) throw new ArgumentException("Duplicate --catalog-dir");
                    directory = value; break;
                case "--pg":
                    if (pg is not null || !System.Text.RegularExpressions.Regex.IsMatch(value, @"\A[1-9][0-9]*\z"))
                        throw new ArgumentException("Invalid/duplicate --pg");
                    pg = value; break;
                case "--policy":
                    if (policy is not null || command != "download")
                        throw new ArgumentException("Unexpected/duplicate --policy");
                    policy = value; break;
                case "--policy-sha256":
                    if (policySha is not null || command != "download")
                        throw new ArgumentException("Unexpected/duplicate --policy-sha256");
                    policySha = value; break;
                case "--format":
                    if (format is not null || command == "download" || value is not ("text" or "json"))
                        throw new ArgumentException("Invalid/duplicate --format");
                    format = value; break;
                case "--output":
                    if (output is not null || command != "download")
                        throw new ArgumentException("Unexpected/duplicate --output");
                    output = value; break;
                default: throw new ArgumentException("Unknown option: " + option);
            }
        }
        if (directory is null) throw new ArgumentException("--catalog-dir is mandatory");
        if (command == "download")
        {
            if (pg is null || query is null || policy is null || policySha is null || output is null)
                throw new ArgumentException("download needs --pg, --policy, --policy-sha256 and --output");
            Console.WriteLine("PUBLISH=DENY SIGNATURE_VERIFIED=FALSE; P1 root/attestation NOT verified");
            var pin = PinnedReleaseSelector.FromLocalFiles(directory, policy, policySha, query, pg);
            using var downloader = new ReadOnlyReleaseDownloader(new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                AutomaticDecompression = DecompressionMethods.None
            });
            var receipt = await downloader.DownloadAsync(pin, output);
            Console.WriteLine($"INTEGRITY_ONLY\t{receipt.Sha256}\t{receipt.Size}\t{receipt.FilePath}");
            return 0;
        }

        var records = CatalogReader.LoadLocal(directory);
        var outputJson = format == "json";
        if (!outputJson)
            Console.WriteLine("SOURCE=LOCAL_UNAUTHENTICATED TRUST=UNVERIFIED PUBLISH=DENY");
        var rows = new List<object>();
        var displayed = 0;
        foreach (var entry in records)
        {
            if (query is not null && !entry.Name.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !entry.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !entry.Description.Contains(query, StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var version in entry.Versions)
            {
                if (pg is not null && version.Major != pg) continue;
                if (outputJson)
                    rows.Add(new
                    {
                        extension = entry.Name,
                        pgMajor = version.Major,
                        upstreamVersion = version.Version,
                        releaseTag = entry.ReleaseTag,
                        assetName = version.Asset,
                        preload = entry.Preload,
                        trust = "UNVERIFIED"
                    });
                else
                    Console.WriteLine($"{entry.Name}\tPG{version.Major}\t{version.Version}\tpreload={entry.Preload}\tUNVERIFIED");
                displayed++;
            }
        }
        if (outputJson)
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                schemaVersion = "pgextwin-cli-local-catalog/v1",
                source = "LOCAL_UNAUTHENTICATED",
                trust = "UNVERIFIED",
                catalogAuthenticated = false,
                signatureVerified = false,
                publicationAuthorized = false,
                distributionAuthorized = false,
                count = displayed,
                records = rows
            }));
        return displayed == 0 ? 3 : 0;
    }
    catch (Exception e) when (e is IOException or InvalidDataException or UnauthorizedAccessException or
        ArgumentException or System.Text.Json.JsonException or InvalidOperationException or
        KeyNotFoundException or HttpRequestException or OperationCanceledException)
    {
        Console.Error.WriteLine("DENY: " + e.Message);
        Usage();
        return 2;
    }
}

static void Usage()
{
    Console.Error.WriteLine("pgextwin --version");
    Console.Error.WriteLine("pgextwin list --catalog-dir PATH [--pg MAJOR] [--format text|json]");
    Console.Error.WriteLine("pgextwin search TERM --catalog-dir PATH [--pg MAJOR] [--format text|json]");
    Console.Error.WriteLine("pgextwin download EXTENSION --pg MAJOR --catalog-dir PATH");
    Console.Error.WriteLine("  --policy EXTERNALLY_AUTHENTICATED_POLICY --policy-sha256 OUT_OF_BAND_SHA256 --output EXISTING_DIR");
    Console.Error.WriteLine("Downloaded ZIP = INTEGRITY_ONLY; no Sigstore, install, bundle, signature, Release or Publisher.");
}
