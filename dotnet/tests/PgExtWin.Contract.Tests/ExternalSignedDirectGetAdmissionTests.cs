using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using PgExtWin.Releases;

internal static class ExternalSignedDirectGetAdmissionTests
{
    private static byte[] Fixture()
    {
        string when = DateTimeOffset.UtcNow.AddMinutes(-2)
            .ToString("yyyy-MM-ddTHH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
        string until = DateTimeOffset.UtcNow.AddHours(6)
            .ToString("yyyy-MM-ddTHH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = "pgextwin-external-direct-get-admission/v1",
            sourceKind = "EXTERNAL_GITHUB_RELEASE_ASSET",
            issuerRepository = "pgextwin/build",
            issuerCommit = new string('a', 40),
            catalogCommit = new string('b', 40),
            issuerEvent = "workflow_dispatch",
            issuerRunId = 123456789L,
            issuerRunAttempt = 1,
            ownerActor = "ShutenOishi",
            ownerId = 27071164L,
            publisherEnvironment = "external-direct-provider-publisher",
            publisherAppId = 5609317L,
            approvedOperation = "ORIGINAL_PROVIDER_GET_ONLY",
            issuedAt = when,
            expiresAt = until,
            downloadAuthorized = true,
            mirrorAuthorized = false,
            redistributionAuthorized = false,
            records = new[] { new
            {
                sourceGroup = "external",
                extension = "pg_trickle",
                pgMajor = "18",
                targetEnvironment = "EDB PostgreSQL 18.6.5 Windows x64",
                sourceRepo = "trickle-labs/pg-trickle",
                repositoryId = 1164857056L,
                releaseTag = "v0.108.3",
                releaseId = 404988260L,
                assetName = "pg_trickle-0.108.3-pg18-windows-amd64.zip",
                assetId = 616203967L,
                originalBytes = 7029107L,
                originalSha256 = "c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b",
                originalProviderUrl = "https://github.com/trickle-labs/pg-trickle/releases/download/v0.108.3/pg_trickle-0.108.3-pg18-windows-amd64.zip",
                licenseUrl = "https://github.com/trickle-labs/pg-trickle/blob/v0.108.3/LICENSE",
                noticeTreatment = "LICENSE in original provider ZIP, all third-party notices separately reviewed before approval.",
                dependencyTreatment = "EDB PostgreSQL 18 Windows x64 dependency prerequisites independently reviewed before approval.",
                approvedOperation = "ORIGINAL_PROVIDER_GET_ONLY",
                downloadAuthorized = true,
                mirrorAuthorized = false
            } }
        });
    }

    private static byte[] Mutate(Action<JsonNode> mutate)
    {
        var doc = JsonNode.Parse(Encoding.UTF8.GetString(Fixture()))!;
        mutate(doc);
        return Encoding.UTF8.GetBytes(doc.ToJsonString());
    }

    private static bool ParseDenied(byte[] json, string pg = "18")
    {
        try
        {
            _ = ExternalSignedDirectGetAdmission.ParseUntrusted(json, pg,
                DateTimeOffset.UtcNow, out _);
            return false;
        }
        catch (Exception ex) when (ex is InvalidDataException or
            JsonException or InvalidOperationException or FormatException)
        {
            return true;
        }
    }

    public static async Task RunAsync(Action<bool, string> check)
    {
        // This is JSON shape validation ONLY. Not signature proof or
        // a positive authorized provider E2E.
        var result = ExternalSignedDirectGetAdmission.ParseUntrusted(Fixture(), "18",
            DateTimeOffset.UtcNow, out var sha);
        check(result.Count == 1 && result[0].Extension == "pg_trickle" &&
              result[0].AssetId == 616203967 &&
              result[0].PgMajor == "18" && sha == new string('a', 40),
              "Synthetic external GET-only signed admission structure is valid, NOT authenticated");

        var tests = new (string Name, string Key, object? Value)[]
        {
            ("wrong owner", "ownerActor", "impostor"),
            ("wrong owner ID", "ownerId", 1),
            ("wrong signer repository", "issuerRepository", "pgextwin/catalog"),
            ("wrong source kind", "sourceKind", "NATIVE_RELEASE"),
            ("wrong issuer event", "issuerEvent", "push"),
            ("wrong attempt", "issuerRunAttempt", 2),
            ("wrong Environment", "publisherEnvironment", "publisher"),
            ("wrong App", "publisherAppId", 1),
            ("wrong operation", "approvedOperation", "MIRROR"),
            ("root mirror", "mirrorAuthorized", true),
            ("root redistribution", "redistributionAuthorized", true),
            ("root unsigned", "downloadAuthorized", false),
            ("bad commit", "issuerCommit", "nope"),
            ("old expiry", "expiresAt", "2020-01-01T00:00:00Z"),
            ("invalid run", "issuerRunId", 0)
        };
        foreach (var (name, key, value) in tests)
        {
            check(ParseDenied(Mutate(doc => doc[key] = JsonSerializer.SerializeToNode(value))),
                  "External signed admission rejects " + name);
        }

        var rows = new (string Name, string Key, object? Value)[]
        {
            ("wrong source", "sourceRepo", "pgextwin/catalog"),
            ("held original provider", "sourceRepo", "laurenz/oracle_fdw"),
            ("invalid target", "targetEnvironment", "Linux arm64"),
            ("wrong PG", "pgMajor", "17"),
            ("wrong asset ID", "assetId", 0),
            ("missing hash", "originalSha256", "bad"),
            ("forged provider URL", "originalProviderUrl", "https://evil.example/zip"),
            ("row mirror", "mirrorAuthorized", true),
            ("row denied download", "downloadAuthorized", false),
            ("row operation", "approvedOperation", "REDISTRIBUTE"),
            ("bad notice", "noticeTreatment", ""),
            ("bad dependency", "dependencyTreatment", "")
        };
        foreach (var (name, key, value) in rows)
        {
            check(ParseDenied(Mutate(doc => doc["records"]![0]![key] =
                JsonSerializer.SerializeToNode(value))), "External admission denies " + name);
        }

        check(ParseDenied(Mutate(doc =>
            ((JsonArray)doc["records"]!).Add(doc["records"]![0]!.DeepClone()))),
            "Duplicate external signed pin denied");
        check(ParseDenied(Mutate(doc => doc["untrustedAuthorization"] = true)),
            "Unknown root field denied");
        check(ParseDenied(Mutate(doc => doc["records"]![0]!["extra"] = true)),
            "Unknown row field denied");
        check(ParseDenied(Mutate(doc => doc["downloadAuthorized"] = 1)),
            "Boolean-int confusion denied");
        check(ParseDenied(Fixture(), "all") == false,
            "Signed-only candidate structure permits all-PG cohort parser");
        check(ParseDenied(Fixture(), "16"),
            "Unsigned PG16 selection cannot use PG18 source");

        // A signed multi-major cohort remains one authenticated subject.
        // Select the requested PG only AFTER every row passed full validation.
        var mixed = Mutate(doc =>
        {
            var vector = doc["records"]![0]!.DeepClone();
            vector["extension"] = "vector";
            vector["pgMajor"] = "16";
            vector["targetEnvironment"] = "EDB PostgreSQL 16 Windows x64";
            vector["sourceRepo"] = "portalcorp/pgvector_compiled";
            vector["repositoryId"] = 835861704L;
            vector["releaseTag"] = "v0.16.105";
            vector["releaseId"] = 182821763L;
            vector["assetName"] = "pgvector-x86_64-pc-windows-msvc-pg16.zip";
            vector["assetId"] = 203009337L;
            vector["originalBytes"] = 163732L;
            vector["originalSha256"] = "a9c63a3e51c09c18f192277a28be3fb021f3872a7cc2d23e4ca06e10f2c99571";
            vector["originalProviderUrl"] = "https://github.com/portalcorp/pgvector_compiled/releases/download/v0.16.105/pgvector-x86_64-pc-windows-msvc-pg16.zip";
            ((JsonArray)doc["records"]!).Add(vector);
        });
        var selectedMajor = ExternalSignedDirectGetAdmission.ParseUntrusted(
            mixed, "16", DateTimeOffset.UtcNow, out _);
        check(selectedMajor.Count == 1 && selectedMajor[0].PgMajor == "16" &&
              selectedMajor[0].Extension == "vector",
              "Mixed signed cohort PG16 selection returns only PG16 original bytes");
        check(ExternalSignedDirectGetAdmission.ParseUntrusted(
            mixed, "all", DateTimeOffset.UtcNow, out _).Count == 2,
            "All-major selection retains both fully validated signed rows");
        check(ParseDenied(mixed, "15"), "Absent PG major fails closed");
        var hiddenBadRow = JsonNode.Parse(Encoding.UTF8.GetString(mixed))!;
        hiddenBadRow["records"]![0]!["mirrorAuthorized"] = true;
        check(ParseDenied(Encoding.UTF8.GetBytes(hiddenBadRow.ToJsonString()), "16"),
              "Selected major cannot hide a malicious unselected signed row");

        var corrupt = Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(Fixture()).Replace(
                "\"mirrorAuthorized\":false", "\"mirrorAuthorized\":false,\"mirrorAuthorized\":true"));
        check(ParseDenied(corrupt), "Duplicate JSON permission key denied");

        // Even a completely valid-looking local JSON is DENIED by an absent
        // trusted independent Build issuer Sigstore signature. No GET happens.
        bool rejected = false;
        try { _ = await ExternalSignedDirectGetAdmission.VerifyAsync(
            Fixture(), Encoding.UTF8.GetBytes("{}"), "18"); }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or
            FormatException or InvalidOperationException) { rejected = true; }
        check(rejected, "Unsigned local external admission never authorizes GET");
    }
}
