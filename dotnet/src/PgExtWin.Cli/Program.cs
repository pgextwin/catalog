using System.Reflection;
using System.Text.Json;
using System.Net;
using PgExtWin.Catalog;
using PgExtWin.Releases;
using PgExtWin.Cli;

return await RunAsync(args);

static async Task<int> RunAsync(string[] args)
{
    try
    {
        // Opt-in diagnostics go to stderr and never alter machine-readable stdout.
        var verboseCount = args.Count(x => x == "--verbose");
        if (verboseCount > 1) throw new ArgumentException("Duplicate --verbose");
        var verbose = verboseCount == 1;
        if (verbose) args = args.Where(x => x != "--verbose").ToArray();
        Action<string>? log = verbose
            ? message => Console.Error.WriteLine($"[{DateTimeOffset.UtcNow:O}] VERBOSE {message}")
            : null;
        if (args.Length > 0 && args[0] == "verify-report")
        {
            log?.Invoke("VERIFY_REPORT_START trust=UNVERIFIED");
            var status = AuthenticatedReportCommand.Run(args);
            log?.Invoke("VERIFY_REPORT_END trust=UNVERIFIED publish=DENY");
            return status;
        }
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
        if (args.Length < 1 || args[0] is not ("list" or "search" or "download" or "download-all"))
            throw new ArgumentException("Only list/search and explicit GET-only download/download-all are available");
        var command = args[0];
        log?.Invoke($"COMMAND_START command={command} publish=DENY");
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
        bool? latest = null;
        while (i < args.Length)
        {
            if (args[i] is "--latest" or "--fixed")
            {
                if (command != "download-all" || latest is not null)
                    throw new ArgumentException("Latest/fixed choice is only allowed once with download-all");
                latest = args[i] == "--latest";
                i++;
                continue;
            }
            if (i + 1 >= args.Length) throw new ArgumentException("Missing option value");
            var option = args[i++]; var value = args[i++];
            switch (option)
            {
                case "--catalog-dir":
                    if (directory is not null) throw new ArgumentException("Duplicate --catalog-dir");
                    directory = value; break;
                case "--pg":
                    if (pg is not null || (value != "all" && !System.Text.RegularExpressions.Regex.IsMatch(value, @"\A[1-9][0-9]*\z")) || (value == "all" && command != "download-all"))
                        throw new ArgumentException("Invalid/duplicate --pg");
                    pg = value; break;
                case "--policy":
                    if (policy is not null || command is not ("download" or "download-all"))
                        throw new ArgumentException("Unexpected/duplicate --policy");
                    policy = value; break;
                case "--policy-sha256":
                    if (policySha is not null || command is not ("download" or "download-all"))
                        throw new ArgumentException("Unexpected/duplicate --policy-sha256");
                    policySha = value; break;
                case "--format":
                    if (format is not null || command is "download" or "download-all" || value is not ("text" or "json"))
                        throw new ArgumentException("Invalid/duplicate --format");
                    format = value; break;
                case "--output":
                    if (output is not null || command is not ("download" or "download-all"))
                        throw new ArgumentException("Unexpected/duplicate --output");
                    output = value; break;
                default: throw new ArgumentException("Unknown option: " + option);
            }
        }
        if (command is "download" or "download-all")
        {
            if (pg is null || (command == "download" && query is null))
                throw new ArgumentException(command + " requires --pg (and an extension for single download)");
            var auto = command == "download-all" &&
                directory is null && policy is null && policySha is null && output is null;
            if (latest == true && !auto)
                throw new ArgumentException("--latest only supports verified automatic Catalog mode");
            if (!auto && (directory is null || policy is null || policySha is null || output is null))
                throw new ArgumentException(command + " needs --catalog-dir, --policy, --policy-sha256 and --output unless using simple download-all");
            Console.WriteLine("PUBLISH=DENY SIGNATURE_VERIFIED=FALSE; Catalog provenance is not original extension Sigstore verification");
            using var downloader = new ReadOnlyReleaseDownloader(new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                AutomaticDecompression = DecompressionMethods.None
            });
            if (command == "download-all")
            {
                if (auto && latest != false)
                {
                    // Default latest from independently Sigstore-verified public Catalog feed.
                    // No anonymous GitHub REST calls; --fixed retains v0.2.2 immutable snapshot.
                    log?.Invoke($"CATALOG_MODE mode=latest pg={pg} authentication=Sigstore");
                    using var selected = await SignedPublicCatalogFeed.AcquireAsync(
                        Directory.GetCurrentDirectory(), pg, progress: log);
                    using var browser = new PinnedBrowserDownloader();
                    var latestBatch = await BatchReleaseDownloader.StageAsync(
                        selected.Pins, pg, Directory.GetCurrentDirectory(),
                        (pin, folder, token) => browser.DownloadAsync(pin, folder, token, log),
                        metadataVerified: false,
                        sourceOverride: "SIGSTORE_SIGNED_CATALOG_FEED_ORIGINAL_ZIPS",
                        progress: log);
                    Console.WriteLine($"CATALOG_COMMIT={selected.Commit} CATALOG_AUTH=SIGSTORE_VERIFIED_FEED RELEASE={selected.SourceReleaseTag}");
                    Console.WriteLine($"BATCH_INTEGRITY_ONLY\tZIP_COUNT={latestBatch.Count}\tBYTES={latestBatch.Bytes}\t{latestBatch.Directory}");
                    return 0;
                }
                // All four optional paths absent: trust anchors live in the
                // current CLI build, never in a live, unpinned HEAD response.
                log?.Invoke($"CATALOG_MODE mode={(auto ? "fixed" : "external")} pg={pg}");
                using var bootstrap = auto
                    ? await TrustedCatalogBootstrap.AcquireAsync(
                        Directory.GetCurrentDirectory(), progress: log)
                    : null;
                var batch = await BatchReleaseDownloader.RunAsync(
                    bootstrap?.CatalogPath ?? directory!,
                    bootstrap?.PolicyFile ?? policy!,
                    bootstrap is null ? policySha! : TrustedCatalogBootstrap.PolicySha256,
                    pg, auto ? Directory.GetCurrentDirectory() : output!, downloader,
                    usePinnedBrowserTransport: auto, progress: log);
                Console.WriteLine($"BATCH_INTEGRITY_ONLY\tZIP_COUNT={batch.Count}\tBYTES={batch.Bytes}\t{batch.Directory}");
                return 0;
            }
            log?.Invoke($"PIN_SELECT_START extension={query} pg={pg}");
            var pin = PinnedReleaseSelector.FromLocalFiles(directory!, policy!, policySha!, query!, pg);
            log?.Invoke($"DOWNLOAD_START extension={pin.Extension} pg={pin.PgMajor} asset={pin.AssetName}");
            var receipt = await downloader.DownloadAsync(pin, output!);
            log?.Invoke($"DOWNLOAD_VERIFIED extension={pin.Extension} pg={pin.PgMajor} bytes={receipt.Size} sha256={receipt.Sha256} trust=INTEGRITY_ONLY");
            Console.WriteLine($"INTEGRITY_ONLY\t{receipt.Sha256}\t{receipt.Size}\t{receipt.FilePath}");
            return 0;
        }
        if (directory is null) throw new ArgumentException("--catalog-dir is mandatory");

        var records = CatalogReader.LoadLocal(directory);
        log?.Invoke($"CATALOG_LOCAL_LOADED records={records.Count} trust=UNVERIFIED");
        var outputJson = format == "json";
        if (!outputJson)
            Console.WriteLine("SOURCE=LOCAL_UNAUTHENTICATED TRUST=UNVERIFIED PUBLISH=DENY");
        var rows = new List<CliCatalogRow>();
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
                    rows.Add(new CliCatalogRow(
                        entry.Name, version.Major, version.Version,
                        entry.ReleaseTag, version.Asset, entry.Preload, "UNVERIFIED"));
                else
                    Console.WriteLine($"{entry.Name}\tPG{version.Major}\t{version.Version}\tpreload={entry.Preload}\tUNVERIFIED");
                displayed++;
            }
        }
        if (outputJson)
            Console.WriteLine(JsonSerializer.Serialize(
                new CliListEnvelope(
                    "pgextwin-cli-local-catalog/v1",
                    "LOCAL_UNAUTHENTICATED", "UNVERIFIED",
                    CatalogAuthenticated: false, SignatureVerified: false,
                    PublicationAuthorized: false, DistributionAuthorized: false,
                    displayed, rows),
                CliJsonContext.Default.CliListEnvelope));
        log?.Invoke($"COMMAND_END rows={displayed} trust=UNVERIFIED");
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
    Console.Error.WriteLine("Add --verbose to any command for timestamped progress on stderr (stdout unchanged).");
    Console.Error.WriteLine("pgextwin verify-report EXTENSION --pg MAJOR --catalog-dir PATH --policy FILE");
    Console.Error.WriteLine("  --policy-sha256 HEX --trusted-root-sha256 HEX --p1-verifier-sha256 HEX");
    Console.Error.WriteLine("  --report FILE --signature FILE --authority-key PEM --authority-key-sha256 HEX");
    Console.Error.WriteLine("pgextwin list --catalog-dir PATH [--pg MAJOR] [--format text|json]");
    Console.Error.WriteLine("pgextwin search TERM --catalog-dir PATH [--pg MAJOR] [--format text|json]");
    Console.Error.WriteLine("pgextwin download EXTENSION --pg MAJOR --catalog-dir PATH");
    Console.Error.WriteLine("  --policy EXTERNALLY_AUTHENTICATED_POLICY --policy-sha256 OUT_OF_BAND_SHA256 --output EXISTING_DIR");
    Console.Error.WriteLine("pgextwin download-all --pg MAJOR|all [--fixed|--latest]");
    Console.Error.WriteLine("  Default/--latest: signed public Catalog feed (no GitHub REST); --fixed: immutable historical snapshot");
    Console.Error.WriteLine("pgextwin download-all --pg MAJOR|all --catalog-dir PATH");
    Console.Error.WriteLine("  --policy EXTERNALLY_AUTHENTICATED_POLICY --policy-sha256 OUT_OF_BAND_SHA256 --output EXISTING_DIR");
    Console.Error.WriteLine("download-all saves one original ZIP per verified Catalog extension and selected PG major in an atomic new subdirectory.");
    Console.Error.WriteLine("Downloaded ZIPs = INTEGRITY_ONLY; no Sigstore, installation, signed bundle or Publisher.");
}
