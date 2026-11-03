using System.Net;
using PgExtWin.Releases;

// Issue #112: a signed Catalog review is never external Publisher authority.
// Native download APIs must refuse the original PG18 external provider assets
// BEFORE any GET, even when a caller fabricates ReleasePins directly.
internal static class ExternalProviderIsolationTests
{
    private sealed class RejectAllNetwork : HttpMessageHandler
    {
        public int Requests { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            throw new InvalidOperationException("Native download issued forbidden external HTTP request");
        }
    }

    public static async Task RunAsync(Action<bool, string> check)
    {
        var destination = Path.Combine(Path.GetTempPath(),
            "pgextwin-external-deny-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(destination);
        try
        {
            const string snapshot = "2d8422be90af3b7e54539ed8649069a2dfb10d48";
            var oracleName = "oracle_fdw-2.9.0-pg18-win64.zip";
            var oracle = new ReleasePins("laurenz/oracle_fdw", "18", "ORACLE_FDW_2_9_0",
                oracleName, "ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678",
                14332609, 335861225, new Dictionary<string, long> { [oracleName] = 442625860 },
                snapshot);
            var pgvectorName = "vector.v0.8.7-pg18.zip";
            var community = new ReleasePins("pgvector", "18", "0.8.7",
                pgvectorName, "7c4ae0e2b2cb1e547779209a34a7d3f05b82fd7912818bf3d7042266eda87e7d",
                838202416, 419235203, new Dictionary<string, long> { [pgvectorName] = 661612613 },
                snapshot);
            foreach (var pin in new[] { oracle, oracle with { Extension = "oracle_fdw" }, community })
            {
                var apiHandler = new RejectAllNetwork();
                using (var api = new ReadOnlyReleaseDownloader(apiHandler))
                {
                    var denied = false;
                    try { await api.DownloadAsync(pin, destination); }
                    catch (InvalidDataException) { denied = true; }
                    check(denied && apiHandler.Requests == 0,
                        "Native REST transport denies external source/naming without GET: " + pin.Extension);
                }
                var browserHandler = new RejectAllNetwork();
                using (var browser = new PinnedBrowserDownloader(browserHandler))
                {
                    var denied = false;
                    try { await browser.DownloadAsync(pin, destination); }
                    catch (InvalidDataException) { denied = true; }
                    check(denied && browserHandler.Requests == 0,
                        "Native browser transport denies external source/naming without GET: " + pin.Extension);
                }
            }
            check(Directory.GetFileSystemEntries(destination).Length == 0,
                "External DENY neither stages nor writes output");
        }
        finally
        {
            Directory.Delete(destination, recursive: true);
        }
    }
}
