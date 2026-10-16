using PgExtWin.Catalog;

return Run(args);

static int Run(string[] args)
{
    try
    {
        if (args.Length == 1 && args[0] is "--help" or "-h" or "help")
        {
            Usage(); return 0;
        }
        if (args.Length < 1 || args[0] is not ("list" or "search"))
            throw new ArgumentException("Only list and search are implemented in PR-1");
        var command = args[0];
        var i = 1;
        string? query = null;
        if (command == "search")
        {
            if (i >= args.Length || args[i].StartsWith('-'))
                throw new ArgumentException("search requires a query");
            query = args[i++];
        }
        string? directory = null;
        string? pg = null;
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
                default: throw new ArgumentException("Unknown option: " + option);
            }
        }
        if (directory is null) throw new ArgumentException("--catalog-dir is mandatory in PR-1");
        var records = CatalogReader.LoadLocal(directory);
        Console.WriteLine("SOURCE=LOCAL_UNAUTHENTICATED TRUST=UNVERIFIED PUBLISH=DENY");
        var displayed = 0;
        foreach (var entry in records)
        {
            if (query is not null && !entry.Name.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !entry.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) &&
                !entry.Description.Contains(query, StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var version in entry.Versions)
            {
                if (pg is not null && version.Major != pg) continue;
                Console.WriteLine($"{entry.Name}\tPG{version.Major}\t{version.Version}\tpreload={entry.Preload}\tUNVERIFIED");
                displayed++;
            }
        }
        return displayed == 0 ? 3 : 0;
    }
    catch (Exception e) when (e is IOException or UnauthorizedAccessException or
        ArgumentException or System.Text.Json.JsonException or InvalidOperationException or KeyNotFoundException)
    {
        Console.Error.WriteLine("DENY: " + e.Message);
        Usage();
        return 2;
    }
}

static void Usage()
{
    Console.Error.WriteLine("pgextwin list --catalog-dir PATH [--pg MAJOR]");
    Console.Error.WriteLine("pgextwin search TERM --catalog-dir PATH [--pg MAJOR]");
    Console.Error.WriteLine("PR-1: local unsigned metadata listing ONLY; no download/verify/install/bundle/publish");
}
