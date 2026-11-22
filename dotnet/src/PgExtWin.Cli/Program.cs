using System.Reflection;
using System.Text.Json;
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
        if (CommandHelp.TryWriteForCommand(args))
            return 0;
        if (args.Length > 0 && args[0] == "verify")
        {
            if (args.Length < 2 || args[1] is not ("report" or "external"))
                throw new ArgumentException("Run pgextwin verify --help for verification commands");
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
            CommandHelp.WriteOverview();
            return 0;
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
                throw new ArgumentException(command == "download"
                    ? "download requires an item name"
                    : "search requires a search term");
            query = args[i++];
        }
        string? directory = null;
        string? pg = null;
        string? output = null;
        string? format = null;
        string? sourceGroup = null;
        string? category = null;
        string? requestedVersion = null;
        string? reviewLedger = null;
        string? inputDir = null;
        var latest = false;
        while (i < args.Length)
        {
            if (args[i] == "--latest")
            {
                if (command != "download-all" || latest)
                    throw new ArgumentException("--latest is only allowed once with download-all");
                latest = true;
                i++;
                continue;
            }
            if (i + 1 >= args.Length) throw new ArgumentException("Missing option value");
            var option = args[i++]; var value = args[i++];
            switch (option)
            {
                case "--catalog-dir":
                    if (directory is not null || command is not ("list" or "search"))
                        throw new ArgumentException("Unexpected/duplicate --catalog-dir");
                    directory = value; break;
                case "--pg":
                    if (pg is not null || (value != "all" && !System.Text.RegularExpressions.Regex.IsMatch(value, command is "list" or "search" ? @"\A[1-9][0-9]*(?:\.[0-9]+)?\z" : @"\A[1-9][0-9]*\z")))
                        throw new ArgumentException("Invalid/duplicate --pg");
                    pg = value; break;
                case "--ledger":
                    if (reviewLedger is not null || command != "verify-external-all")
                        throw new ArgumentException("Unexpected/duplicate --ledger");
                    reviewLedger = value; break;
                case "--input-dir":
                    if (inputDir is not null || command != "verify-external-all")
                        throw new ArgumentException("Unexpected/duplicate --input-dir");
                    inputDir = value; break;
                case "--version":
                    if (command is not ("download" or "download-all"))
                        throw new ArgumentException("Use download ITEM --version EXACT to select a recorded version");
                    if (requestedVersion is not null)
                        throw new ArgumentException("Duplicate --version");
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
        if (command == "verify-external-all")
        {
            if (reviewLedger is null || inputDir is null || pg is null ||
                sourceGroup is not null || format is not null)
                throw new ArgumentException("verify external requires --ledger, --input-dir and --pg");
            // Local-only ZIP integrity verification. No network or source admission.
            var verified = ExternalOriginalZipBatch.VerifyLocal(reviewLedger, inputDir, pg);
            Console.WriteLine($"EXTERNAL_BULK_INTEGRITY_ONLY ZIP_COUNT={verified.Count} BYTES={verified.Bytes} MEMBERS={verified.Members} " +
                "SIGNATURE_VERIFIED=FALSE DOWNLOAD_AUTHORIZED=FALSE PUBLISH=DENY");
            return 0;
        }
        if (command is "download" or "download-all")
        {
            var external = sourceGroup == "external" || sourceGroup is null &&
                (command == "download" || category is not null);
            var outputParent = output ?? Directory.GetCurrentDirectory();
            if (external)
            {
                if (latest)
                    throw new ArgumentException("--latest applies to pgextwin downloads");
                log?.Invoke("EXTERNAL_DIRECT_GET_START source=PROVIDER_RELEASE_ASSET");
                var result = await ExternalSignedCatalogCohort.DownloadAsync(
                    pg ?? "all", outputParent, category, query, requestedVersion);
                Console.WriteLine($"EXTERNAL_ORIGINAL_GET_ONLY\tFILE_COUNT={result.Count}\tBYTES={result.Bytes}\t{result.Directory}");
                return 0;
            }
            if (sourceGroup == "all")
                throw new InvalidDataException("Mixed/unsigned external download denied; no fallback");
            if (category is not null)
                throw new ArgumentException("--category applies to external downloads");
            if (requestedVersion is not null && command != "download")
                throw new ArgumentException("--version requires download ITEM --source pgextwin with the signed Catalog feed");
            if (pg is null || query is not null && pg == "all")
                throw new ArgumentException(query is null
                    ? "download-all requires --pg MAJOR or --pg all for pgextwin downloads"
                    : "download requires --pg MAJOR for pgextwin downloads");
            Console.WriteLine("PUBLISH=DENY SIGNATURE_VERIFIED=FALSE; Catalog provenance is not original extension Sigstore verification");
            log?.Invoke($"CATALOG_MODE mode={(requestedVersion is null ? "latest" : "exact")} pg={pg} authentication=Sigstore");
            var selected = await SignedPublicCatalogFeed.AcquireAsync(pg, query, requestedVersion, progress: log);
            using var browser = new PinnedBrowserDownloader();
            if (query is not null)
            {
                var single = selected.Pins.Single();
                var original = await browser.DownloadAsync(single, outputParent, progress: log);
                Console.WriteLine($"CATALOG_COMMIT={selected.Commit} CATALOG_AUTH=SIGSTORE_VERIFIED_FEED RELEASE={selected.SourceReleaseTag}");
                Console.WriteLine($"CATALOG_PACKAGE\t{single.Extension}\tPG{single.PgMajor}\t{single.Version}\t{single.Tag}\t{single.License!.Name}\t{string.Join(' ', single.License.EvidenceUrls)}");
                Console.WriteLine($"INTEGRITY_ONLY\t{original.Sha256}\t{original.Size}\t{original.FilePath}");
                return 0;
            }
            var batch = await BatchReleaseDownloader.StageAsync(
                selected.Pins, pg, outputParent,
                (pin, folder, token) => browser.DownloadAsync(pin, folder, token, log),
                approvedMajors: selected.ApprovedMajors, progress: log);
            Console.WriteLine($"CATALOG_COMMIT={selected.Commit} CATALOG_AUTH=SIGSTORE_VERIFIED_FEED RELEASE={selected.SourceReleaseTag}");
            Console.WriteLine($"BATCH_INTEGRITY_ONLY\tZIP_COUNT={batch.Count}\tBYTES={batch.Bytes}\t{batch.Directory}");
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
        CommandHelp.WriteOverview();
        return 2;
    }
}
