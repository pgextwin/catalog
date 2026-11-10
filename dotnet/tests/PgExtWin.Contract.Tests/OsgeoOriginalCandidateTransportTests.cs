using System.Net;
using System.Text;
using PgExtWin.Releases;

// All HTTP is synthetic; no owner signature, provider GET or Publisher.
internal static class OsgeoOriginalCandidateTransportTests
{
    private sealed class Stub(Func<HttpRequestMessage, HttpResponseMessage> callback)
        : HttpMessageHandler
    {
        public int Calls { get; private set; }
        public string? LastUrl { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            LastUrl = request.RequestUri?.AbsoluteUri;
            return Task.FromResult(callback(request));
        }
    }

    private static bool Denied(Action action)
    {
        try { action(); return false; }
        catch (Exception error) when (error is InvalidDataException or IOException
            or HttpRequestException) { return true; }
    }

    private static async Task<bool> DeniedAsync(
        OsgeoOriginalCandidateTransport client, OsgeoOriginalCandidatePin pin,
        string folder)
    {
        try { await client.DownloadAsync(pin, folder); return false; }
        catch (Exception error) when (error is InvalidDataException or IOException
            or HttpRequestException) { return true; }
    }

    public static async Task RunAsync(Action<bool, string> check)
    {
        var pin = OsgeoOriginalCandidateTransport.Pinned;
        OsgeoOriginalCandidateTransport.ValidatePin(pin);
        check(pin.OriginalBytes == 83_320_975L &&
              pin.OriginalBytes > ExternalOriginalZipIntegrity.MaxOriginalBytes &&
              pin.OriginalSha256.Length == 64,
              "OSGeo pin requires exact single oversized official original");
        check(Denied(() => OsgeoOriginalCandidateTransport.ValidatePin(
            pin with { OriginalUrl = "https://github.com/fake/release.zip" })),
            "Off-origin OSGeo GET rejected");
        check(Denied(() => OsgeoOriginalCandidateTransport.ValidatePin(
            pin with { OriginalUrl = pin.OriginalUrl + "?mirror=1" })),
            "OSGeo query string substitution denied");
        check(Denied(() => OsgeoOriginalCandidateTransport.ValidatePin(
            pin with { OriginalBytes = 83_320_976L })),
            "Unbounded OSGeo size relaxation denied");
        check(Denied(() => OsgeoOriginalCandidateTransport.ValidatePin(
            pin with { OriginalSha256 = new string('0', 64) })),
            "OSGeo checksum substitution denied");
        check(Denied(() => OsgeoOriginalCandidateTransport.ValidatePin(
            pin with { PgMajor = "17" })),
            "Unverified OSGeo cross-major compatibility denied");
        check(Denied(() => ExternalOriginalZipIntegrity.VerifyOsgeoExactCandidate(
            new byte[] { 0x50, 0x4b, 0x03, 0x04 }, 4, pin.OriginalSha256)),
            "OSGeo scoped integrity denies arbitrary original size");
        var folder = Path.Combine(Path.GetTempPath(),
            "pgextwin-osgeo-synthetic-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            foreach (var status in new[] { HttpStatusCode.Redirect,
                HttpStatusCode.NotFound, HttpStatusCode.ServiceUnavailable })
            {
                var stub = new Stub(_ => new HttpResponseMessage(status) {
                    Content = new ByteArrayContent(Encoding.UTF8.GetBytes("not zip"))
                });
                using var transport = new OsgeoOriginalCandidateTransport(stub);
                check(await DeniedAsync(transport, pin, folder) &&
                      stub.Calls == 1 && stub.LastUrl == pin.OriginalUrl &&
                      Directory.GetFiles(folder).Length == 0,
                      "OSGeo rejects HTTP status/redirect with no fallback: " + status);
            }
            var wrong = new Stub(_ => new HttpResponseMessage(HttpStatusCode.OK) {
                Content = new ByteArrayContent(new byte[] { 0x50, 0x4b, 0x03, 0x04 })
            });
            using (var transport = new OsgeoOriginalCandidateTransport(wrong))
                check(await DeniedAsync(transport, pin, folder) &&
                      Directory.GetFiles(folder).Length == 0,
                      "OSGeo rejects wrong declared ZIP Content-Length");
            var html = new Stub(_ => new HttpResponseMessage(HttpStatusCode.OK) {
                Content = new StringContent("<html>fake</html>", Encoding.UTF8, "text/html")
            });
            using (var transport = new OsgeoOriginalCandidateTransport(html))
                check(await DeniedAsync(transport, pin, folder),
                      "OSGeo rejects a provider HTML substitute");
            File.WriteAllText(Path.Combine(folder, pin.AssetName), "previous");
            var shouldNotGet = new Stub(_ => throw new InvalidOperationException(
                "Destination collision must deny before networking"));
            using (var transport = new OsgeoOriginalCandidateTransport(shouldNotGet))
                check(await DeniedAsync(transport, pin, folder) &&
                      shouldNotGet.Calls == 0,
                      "Existing candidate original prevents any network request");
        }
        finally { Directory.Delete(folder, recursive: true); }
    }
}
