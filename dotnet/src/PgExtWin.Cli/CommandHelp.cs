namespace PgExtWin.Cli;

internal static class CommandHelp
{
    public static void WriteOverview() => Console.Error.WriteLine("""
        pgextwin — browse and download Windows x64 PostgreSQL packages

          pgextwin list                  List available external packages.
          pgextwin search TERM           Search available external packages.
          pgextwin download ITEM         Download one named item.
          pgextwin download-all          Download a selection in bulk.
          pgextwin verify external       Check local provider ZIPs against a review ledger.
          pgextwin verify report         Authenticate a signed report for one extension.
          pgextwin --version             Show the CLI version.
          pgextwin --help                Show this overview.

        Run pgextwin COMMAND --help for command usage.
        Add --verbose for timestamped diagnostics on stderr.
        """);

    public static bool TryWriteForCommand(string[] args)
    {
        var command = args switch
        {
            [var name, "--help" or "-h"] => name,
            ["verify", var subcommand, "--help" or "-h"] => "verify " + subcommand,
            _ => null
        };
        var help = command switch
        {
            "list" => """
                List available packages or browse a local Catalog.

                  pgextwin list [--source external] [--category CATEGORY] [--pg MAJOR|all] [--format text|json]
                  pgextwin list --catalog-dir DIR [--source pgextwin|external|all] [--pg MAJOR|all] [--format text|json]

                Categories are extensions, spatial, tools, and drivers.
                External packages are listed by default. Local Catalog rows show unsigned metadata.
                Omit --pg to include all recorded majors. Major-independent packages match any major.
                """,
            "search" => """
                Search available packages or a local Catalog for TERM.

                  pgextwin search TERM [--source external] [--category CATEGORY] [--pg MAJOR|all] [--format text|json]
                  pgextwin search TERM --catalog-dir DIR [--source pgextwin|external|all] [--pg MAJOR|all] [--format text|json]

                Categories are extensions, spatial, tools, and drivers.
                External packages are searched by default. Local Catalog rows show unsigned metadata.
                Omit --pg to include all recorded majors. Major-independent packages match any major.
                """,
            "download" => """
                Download one named item for the selected PostgreSQL target.

                  pgextwin download ITEM [--source external] [--version EXACT] [--pg MAJOR|all] [--category CATEGORY] [--output DIR]
                  pgextwin download ITEM --source pgextwin --pg MAJOR [--output DIR]
                  pgextwin download ITEM --catalog-dir DIR --policy FILE --policy-sha256 HEX --pg MAJOR --output DIR

                Named downloads default to external. Omit --pg to include all recorded majors.
                --version selects an exact recorded external version. The default is the version marked latest in the Catalog.
                Categories are extensions, spatial, tools, and drivers.
                Use an existing output directory. The default is the current directory.
                """,
            "download-all" => """
                Download a selection of packages in bulk.

                  pgextwin download-all [--source pgextwin] --pg MAJOR|all [--output DIR] [--latest|--fixed]
                  pgextwin download-all --source external [--pg MAJOR|all] [--category CATEGORY] [--output DIR]
                  pgextwin download-all --catalog-dir DIR --policy FILE --policy-sha256 HEX --pg MAJOR|all --output DIR

                With no source or category specified, bulk downloads use the latest signed pgextwin Catalog feed.
                Use --fixed for the historical pgextwin snapshot.
                External downloads default to all recorded majors. Categories are extensions, spatial, tools, and drivers.
                Use download ITEM [--version EXACT] to select one external item.
                Use an existing output directory. The default is the current directory.
                """,
            "verify" => """
                Verify local inputs.

                  pgextwin verify external --help    Check local provider ZIPs against a review ledger.
                  pgextwin verify report --help      Authenticate a signed report for one extension.
                """,
            "verify external" or "verify-external-all" => """
                Check the size, SHA-256, and structure of local provider ZIPs against a review ledger.

                  pgextwin verify external --ledger FILE --input-dir DIR --pg MAJOR|all

                The input directory contains pgMAJOR/EXTENSION/ASSET_NAME paths.
                """,
            "verify report" or "verify-report" => """
                Authenticate a signed report for one extension against independently pinned local inputs.

                  pgextwin verify report ITEM --pg MAJOR --catalog-dir DIR --policy FILE --policy-sha256 HEX
                    --trusted-root-sha256 HEX --p1-verifier-sha256 HEX --report FILE --signature FILE
                    --authority-key PEM --authority-key-sha256 HEX
                """,
            _ => null
        };
        if (help is null)
            return false;

        Console.Error.WriteLine(help);
        return true;
    }
}
