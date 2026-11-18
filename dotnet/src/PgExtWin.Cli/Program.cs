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
        if (args.Length > 0 && args[0] == "verify")
        {
            if (args.Length < 2 || args[1] is not ("report" or "external"))
                throw new ArgumentException("Use verify report or verify external");
            var verb = args[1] == "report" ? "verify-report" : "verify-external-all";
            args = [verb, .. args[2..]];
        }
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
        if (args.Length < 1 || args[0] is not ("list" or "search" or "download" or "download-all" or "verify-external-all"))
            throw new ArgumentException("Unknown command. Run pgextwin --help");
        var command = args[0];
        log?.Invoke($"COMMAND_START command={command} publish=DENY");
        var i = 1;
        string? query = null;
        if (command is "search" or "download")
        {
            if (i >= args.Length || args[i].StartsWith('-'))
                throw new ArgumentException(command + " requires an item name or search term");
            query = args[i++];
        }
        string? directory = null;
        string? pg = null;
        string? policy = null;
        string? policySha = null;
        string? output = null;
        string? format = null;
        string? sourceGroup = null;
        string? category = null;
        string? requestedExtension = null;
        string? requestedVersion = null;
        string? reviewLedger = null;
        string? inputDir = null;
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
                    if (pg is not null || (value != "all" && !System.Text.RegularExpressions.Regex.IsMatch(value, command is "list" or "search" ? @"\A[1-9][0-9]*(?:\.[0-9]+)?\z" : @"\A[1-9][0-9]*\z")))
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
                case "--ledger":
                    if (reviewLedger is not null || command != "verify-external-all")
                        throw new ArgumentException("Unexpected/duplicate --ledger");
                    reviewLedger = value; break;
                case "--input-dir":
                    if (inputDir is not null || command != "verify-external-all")
                        throw new ArgumentException("Unexpected/duplicate --input-dir");
                    inputDir = value; break;
                case "--extension":
                    if (command != "download-all" || requestedExtension is not null)
                        throw new ArgumentException("--extension only supports external download-all once");
                    requestedExtension = value; break;
                case "--version":
                    if (command is not ("download" or "download-all") || requestedVersion is not null)
                        throw new ArgumentException("--version requires a named external download");
                    requestedVersion = value; break;
                case "--source":
                    if (sourceGroup is not null || value is not ("external" or "pgextwin" or "all"))
                        throw new ArgumentException("Invalid/duplicate --source");
                    sourceGroup = value; break;
                case "--category":
                    if (category is not null || value is not ("extensions" or "spatial" or "tools" or "drivers") ||
                        command == "verify-external-all")
                        throw new ArgumentException("Invalid/duplicate --category");
                    category = value; break;
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
        if (requestedExtension is not null && sourceGroup != "external")
            throw new ArgumentException("--extension requires --source external");
        if (command == "verify-external-all")
        {
            if (reviewLedger is null || inputDir is null || pg is null ||
                directory is not null || sourceGroup is not null || policy is not null ||
                policySha is not null || output is not null || format is not null || latest is not null)
                throw new ArgumentException("verify-external-all requires --ledger, --input-dir and --pg only");
            // Local-only ZIP integrity verification. No network or source admission.
            var verified = ExternalOriginalZipBatch.VerifyLocal(reviewLedger, inputDir, pg);
            Console.WriteLine($"EXTERNAL_BULK_INTEGRITY_ONLY ZIP_COUNT={verified.Count} BYTES={verified.Bytes} MEMBERS={verified.Members} " +
                "SIGNATURE_VERIFIED=FALSE DOWNLOAD_AUTHORIZED=FALSE PUBLISH=DENY");
            return 0;
        }
        if (command is "download" or "download-all")
        {
            var localPolicy = directory is not null || policy is not null || policySha is not null;
            var external = sourceGroup == "external" || sourceGroup is null &&
                !localPolicy && (command == "download" || category is not null);
            if (external)
            {
                if (localPolicy || latest is not null)
                    throw new ArgumentException("External downloads use Catalog records. Use --pg, --category or --output to select them.");
                log?.Invoke("EXTERNAL_DIRECT_GET_START source=PROVIDER_RELEASE_ASSET");
                var parent = output ?? Directory.GetCurrentDirectory();
                if (requestedExtension is not null && category is null)
                {
                    // Keep the legacy filtered ZIP batch's path and receipt.
                    var legacy = await ExternalSignedCatalogCohort.StageDirectAsync(
                        pg ?? "all", parent, requestedExtension: requestedExtension,
                        requestedVersion: requestedVersion);
                    Console.WriteLine($"EXTERNAL_ORIGINAL_GET_ONLY\tZIP_COUNT={legacy.Count}\tBYTES={legacy.Bytes}\t{legacy.Directory}");
                    return 0;
                }
                var result = await ExternalSignedCatalogCohort.DownloadAsync(
                    pg ?? "all", parent, category, query ?? requestedExtension, requestedVersion);
                Console.WriteLine($"EXTERNAL_ORIGINAL_GET_ONLY\tFILE_COUNT={result.Count}\tBYTES={result.Bytes}\t{result.Directory}");
                return 0;
            }
            if (sourceGroup == "all")
                throw new InvalidDataException("Mixed/unsigned external download denied; no fallback");
            if (category is not null || requestedVersion is not null)
                throw new ArgumentException("--category and --version apply to external downloads");
            if (pg is null || query is not null && pg == "all")
                throw new ArgumentException(command + " requires a PostgreSQL major for pgextwin downloads");
            var auto = !localPolicy;
            if (!auto && (latest == true || directory is null || policy is null || policySha is null || output is null))
                throw new ArgumentException("Explicit policy requires --catalog-dir, --policy, --policy-sha256 and --output");
            var outputParent = output ?? Directory.GetCurrentDirectory();
            Console.WriteLine("PUBLISH=DENY SIGNATURE_VERIFIED=FALSE; Catalog provenance is not original extension Sigstore verification");
            using var downloader = new ReadOnlyReleaseDownloader(new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                AutomaticDecompression = DecompressionMethods.None
            });
            if (auto && latest != false)
            {
                log?.Invoke($"CATALOG_MODE mode=latest pg={pg} authentication=Sigstore");
                using var selected = await SignedPublicCatalogFeed.AcquireAsync(
                    outputParent, pg, progress: log);
                using var browser = new PinnedBrowserDownloader();
                if (query is not null)
                {
                    var single = selected.Pins.SingleOrDefault(
                        x => x.Extension.Equals(query, StringComparison.OrdinalIgnoreCase))
                        ?? throw new InvalidDataException("No signed Catalog download matches the item and PostgreSQL major");
                    var original = await browser.DownloadAsync(single, outputParent, progress: log);
                    Console.WriteLine($"CATALOG_COMMIT={selected.Commit} CATALOG_AUTH=SIGSTORE_VERIFIED_FEED RELEASE={selected.SourceReleaseTag}");
                    Console.WriteLine($"INTEGRITY_ONLY\t{original.Sha256}\t{original.Size}\t{original.FilePath}");
                    return 0;
                }
                var latestBatch = await BatchReleaseDownloader.StageAsync(
                    selected.Pins, pg, outputParent,
                    (pin, folder, token) => browser.DownloadAsync(pin, folder, token, log),
                    metadataVerified: false,
                    sourceOverride: "SIGSTORE_SIGNED_CATALOG_FEED_ORIGINAL_ZIPS",
                    progress: log, approvedMajors: selected.ApprovedMajors);
                Console.WriteLine($"CATALOG_COMMIT={selected.Commit} CATALOG_AUTH=SIGSTORE_VERIFIED_FEED RELEASE={selected.SourceReleaseTag}");
                Console.WriteLine($"BATCH_INTEGRITY_ONLY\tZIP_COUNT={latestBatch.Count}\tBYTES={latestBatch.Bytes}\t{latestBatch.Directory}");
                return 0;
            }
            if (command == "download-all")
            {
                // All four optional paths absent: trust anchors live in the
                // current CLI build, never in a live, unpinned HEAD response.
                log?.Invoke($"CATALOG_MODE mode={(auto ? "fixed" : "external")} pg={pg}");
                using var bootstrap = auto
                    ? await TrustedCatalogBootstrap.AcquireAsync(
                        outputParent, progress: log)
                    : null;
                var batch = await BatchReleaseDownloader.RunAsync(
                    bootstrap?.CatalogPath ?? directory!,
                    bootstrap?.PolicyFile ?? policy!,
                    bootstrap is null ? policySha! : TrustedCatalogBootstrap.PolicySha256,
                    pg, outputParent, downloader,
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
        if (directory is null)
        {
            if (sourceGroup is not (null or "external"))
                throw new ArgumentException("Use --catalog-dir to browse local pgextwin or candidate metadata");
            var downloads = await ExternalSignedCatalogCohort.ListDownloadsAsync(pg ?? "all", category, query);
            if (format == "json")
                Console.WriteLine(JsonSerializer.Serialize(downloads.ToArray(),
                    CliJsonContext.Default.ExternalDownloadItemArray));
            else
                foreach (var item in downloads)
                {
                    var target = item.PgMajor is null ? "any PG" : "PG" + item.PgMajor;
                    Console.WriteLine($"{item.Name}\t{item.Category}\t{target}\t{item.Version}\t{item.License}\t{item.AssetName}");
                }
            return downloads.Count == 0 ? 3 : 0;
        }
        if (category is not null)
            throw new ArgumentException("--category filters downloadable entries. Omit --catalog-dir to use it.");

        var records = CatalogReader.LoadLocal(directory);
        var externalRows = new List<CliExternalSourceRow>();
        log?.Invoke($"CATALOG_LOCAL_LOADED records={records.Count} trust=UNVERIFIED");
        var outputJson = format == "json";
        if (!outputJson)
            Console.WriteLine("SOURCE=LOCAL_UNAUTHENTICATED TRUST=UNVERIFIED PUBLISH=DENY");
        var rows = new List<CliCatalogRow>();
        var displayed = 0;
        if (sourceGroup != "external") foreach (var entry in records)
        {
            if (query is not null && !entry.Name.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !entry.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !entry.Description.Contains(query, StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var version in entry.Versions)
            {
                if (pg is not (null or "all") && version.Major != pg) continue;
                if (outputJson)
                    rows.Add(new CliCatalogRow(
                        entry.Name, version.Major, version.Version,
                        entry.ReleaseTag, version.Asset, entry.Preload, "UNVERIFIED"));
                else
                    Console.WriteLine($"{entry.Name}\tPG{version.Major}\t{version.Version}\tpreload={entry.Preload}\tUNVERIFIED");
                displayed++;
            }
        }
        if (sourceGroup is "external" or "all")
        {
            // Metadata discovery only. No SHA256, trust, permission or source promotion.
            foreach (var entry in WindowsSourceRegistry.LoadLocal(directory))
            {
                if (query is not null && !entry.Extension.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                    !entry.Provider.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                    !entry.UpstreamVersion.Contains(query, StringComparison.OrdinalIgnoreCase)) continue;
                if (pg is not (null or "all") && entry.PgMajor != pg) continue;
                if (outputJson)
                    externalRows.Add(new CliExternalSourceRow(entry.Extension, entry.PgMajor,
                        entry.UpstreamVersion, entry.Provider, entry.ProviderType,
                        entry.ReleaseTag, entry.AssetName, entry.Lifecycle, entry.Historical,
                        entry.VerificationState, false));
                else
                    Console.WriteLine(entry.Extension + "\tPG" + entry.PgMajor + "\t" +
                        entry.UpstreamVersion + "\tsource=external\tprovider=" + entry.Provider +
                        "\t" + entry.VerificationState + "\tDOWNLOAD_DENY");
                displayed++;
            }
        }
        if (outputJson && sourceGroup is "external" or "all")
            Console.WriteLine(JsonSerializer.Serialize(
                new CliSourceListEnvelope("pgextwin-cli-source-discovery/v1",
                    sourceGroup!, "UNVERIFIED", false, false, false, false,
                    displayed, rows, externalRows), CliJsonContext.Default.CliSourceListEnvelope));
        else if (outputJson)
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
    Console.Error.WriteLine("""
        pgextwin — download Windows x64 packages without a PostgreSQL installation

          list [--category CATEGORY] [--pg MAJOR] [--format text|json]
          search TERM [--category CATEGORY] [--pg MAJOR] [--format text|json]
          download ITEM [--source external] [--pg MAJOR|all] [--category CATEGORY] [--version EXACT] [--output DIR]
          download ITEM --source pgextwin --pg MAJOR [--output DIR]
          download-all --source external [--category CATEGORY] [--pg MAJOR|all] [--output DIR]
          download-all [--source pgextwin] --pg MAJOR|all [--output DIR] [--latest|--fixed]
          verify external --ledger FILE --input-dir DIR --pg MAJOR|all
          verify report ITEM --pg MAJOR --catalog-dir DIR --policy FILE --policy-sha256 HEX
            --trusted-root-sha256 HEX --p1-verifier-sha256 HEX --report FILE --signature FILE
            --authority-key PEM --authority-key-sha256 HEX
          --version | --help

        Categories: extensions, spatial, tools, drivers.
        List, search and named downloads default to external. External --pg is optional.
        A PostgreSQL major filters compatible files. Major-independent files match any major.
        --version selects an exact recorded version for a named external item.
        Bulk downloads default to the signed pgextwin feed and require --pg in that mode.
        Use an existing output directory (default: current directory). Files are never run.

        Local views: list/search --catalog-dir DIR [--source pgextwin|external|all] [--pg MAJOR] [--format text|json]
        Local policy: download/download-all --catalog-dir DIR --policy FILE --policy-sha256 HEX --pg MAJOR --output DIR
        Add --verbose for timestamped progress on stderr.
        """);
}
