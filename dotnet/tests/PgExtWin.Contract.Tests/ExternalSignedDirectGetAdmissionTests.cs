using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Cryptography;
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

    private static byte[] LatestPins(byte[] admission)
    {
        using var doc = JsonDocument.Parse(admission);
        var root = doc.RootElement;
        var row = root.GetProperty("records")[0];
        var pins = new[]
        {
            new
            {
                extension = row.GetProperty("extension").GetString(),
                pgMajor = row.GetProperty("pgMajor").GetString(),
                sourceRepo = row.GetProperty("sourceRepo").GetString(),
                repositoryId = row.GetProperty("repositoryId").GetInt64(),
                releaseTag = row.GetProperty("releaseTag").GetString(),
                releaseId = row.GetProperty("releaseId").GetInt64(),
                assetName = row.GetProperty("assetName").GetString(),
                assetId = row.GetProperty("assetId").GetInt64(),
                originalBytes = row.GetProperty("originalBytes").GetInt64(),
                originalSha256 = row.GetProperty("originalSha256").GetString(),
                originalProviderUrl = row.GetProperty("originalProviderUrl").GetString()
            }
        };
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = "pgextwin-external-latest-original-pins/v1",
            issuerRunId = root.GetProperty("issuerRunId").GetInt64(),
            admissionSha256 = Convert.ToHexString(SHA256.HashData(admission)).ToLowerInvariant(),
            records = pins
        });
    }

    private static bool LatestBindingDenied(byte[] latest, byte[] admission)
    {
        try
        {
            ExternalSignedDirectGetAdmission.ValidateLatestBinding(
                latest, admission, 123456789L);
            return false;
        }
        catch (Exception ex) when (ex is InvalidDataException or
            JsonException or InvalidOperationException or FormatException)
        { return true; }
    }

    private static bool ParseDenied(byte[] json, string pg = "18",
        string? extension = null, string? version = null)
    {
        try
        {
            _ = ExternalSignedDirectGetAdmission.ParseUntrusted(json, pg,
                DateTimeOffset.UtcNow, out _, extension, version);
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
        var admission = Fixture();
        var latestPins = LatestPins(admission);
        check(ExternalSignedCatalogCohort.LatestRunId(latestPins) == 123456789L,
            "Automatic external GET selects the explicit Catalog latest Run, not the numerically largest archive");
        ExternalSignedDirectGetAdmission.ValidateLatestBinding(
            latestPins, admission, 123456789L);
        check(true, "Catalog latest release identities and exact admission bytes match");
        foreach (var bad in new byte[][]
        {
            Encoding.UTF8.GetBytes("[]"),
            Encoding.UTF8.GetBytes("{\"schemaVersion\":\"wrong\"}"),
        })
        {
            var denied = false;
            try { _ = ExternalSignedCatalogCohort.LatestRunId(bad); }
            catch (Exception ex) when (ex is InvalidDataException or JsonException or InvalidOperationException)
            { denied = true; }
            check(denied, "Automatic external GET denies an absent or malformed Catalog latest pin set");
        }

        var tamperedLatest = JsonNode.Parse(Encoding.UTF8.GetString(latestPins))!;
        tamperedLatest["records"]![0]!["releaseTag"] = "v0.108.4";
        check(LatestBindingDenied(Encoding.UTF8.GetBytes(tamperedLatest.ToJsonString()), admission),
            "New Catalog latest release cannot reuse an older signed authorization");
        tamperedLatest = JsonNode.Parse(Encoding.UTF8.GetString(latestPins))!;
        tamperedLatest["admissionSha256"] = new string('0', 64);
        check(LatestBindingDenied(Encoding.UTF8.GetBytes(tamperedLatest.ToJsonString()), admission),
            "Catalog latest pointer cannot substitute signed admission bytes");
        tamperedLatest = JsonNode.Parse(Encoding.UTF8.GetString(latestPins))!;
        tamperedLatest["issuerRunId"] = 123456788L;
        check(LatestBindingDenied(Encoding.UTF8.GetBytes(tamperedLatest.ToJsonString()), admission),
            "Catalog latest pointer Run must match the signed issuer Run");
        tamperedLatest = JsonNode.Parse(Encoding.UTF8.GetString(latestPins))!;
        ((JsonArray)tamperedLatest["records"]!).Clear();
        check(LatestBindingDenied(Encoding.UTF8.GetBytes(tamperedLatest.ToJsonString()), admission),
            "Catalog latest pointer must cover the entire signed cohort");
        tamperedLatest = JsonNode.Parse(Encoding.UTF8.GetString(latestPins))!;
        tamperedLatest["untrustedAuthorization"] = true;
        check(LatestBindingDenied(Encoding.UTF8.GetBytes(tamperedLatest.ToJsonString()), admission),
            "Catalog latest pointer rejects unknown authorization fields");

        // This is JSON shape validation ONLY. Not signature proof or
        // a positive authorized provider E2E.
        var result = ExternalSignedDirectGetAdmission.ParseUntrusted(Fixture(), "18",
            DateTimeOffset.UtcNow, out var sha);
        check(result.Count == 1 && result[0].Extension == "pg_trickle" &&
              result[0].AssetId == 616203967 &&
              result[0].PgMajor == "18" && sha == new string('a', 40),
              "Synthetic external GET-only signed admission structure is valid, NOT authenticated");

        check(ExternalSignedDirectGetAdmission.ParseUntrusted(
            Fixture(), "18", DateTimeOffset.UtcNow, out _, "pg_trickle", "0.108.3").Count == 1,
            "Exact signed extension/version pin retains eligible external original ZIP");
        check(ParseDenied(Fixture(), "18", "pg_trickle", "0.108.2"),
            "Unreviewed version is never fetched, even if a public release exists");
        check(ParseDenied(Fixture(), "18", "pg_trickle", "0.108.30"),
            "Version pin rejects approximate and prefix matches");
        check(ParseDenied(Fixture(), "18", "hypopg", "0.108.3"),
            "Signed pin for another extension cannot satisfy a version request");
        check(ParseDenied(Fixture(), "18", null, "0.108.3"),
            "Version without extension is rejected");
        check(ParseDenied(Fixture(), "18", "pg_trickle", "../0.108.3"),
            "Unsafe version syntax denied");
        check(ParseDenied(Fixture(), "18", "../pg_trickle"),
            "Unsafe extension syntax denied");

        // Upstream PGroonga names its exact original ZIPs
        // pgroonga-VERSION-postgresql-MAJOR-x64.zip, not -pgMAJOR-.
        // This synthetic shape is NEVER independent signed admission.
        var pgroongaOriginal = Mutate(doc =>
        {
            var row = doc["records"]![0]!;
            row["extension"] = "pgroonga";
            row["pgMajor"] = "14";
            row["targetEnvironment"] = "EDB PostgreSQL 14.24.0 Windows x64";
            row["sourceRepo"] = "pgroonga/pgroonga";
            row["repositoryId"] = 29133291L;
            row["releaseTag"] = "4.1.0";
            row["releaseId"] = 407467158L;
            row["assetName"] = "pgroonga-4.1.0-postgresql-14-x64.zip";
            row["assetId"] = 623766852L;
            row["originalBytes"] = 53806600L;
            row["originalSha256"] = "39d2685f234c8b45563f57f113bd8c84cc1ae4e8c0c22e6826bf168ba1c0ab39";
            row["originalProviderUrl"] =
                "https://github.com/pgroonga/pgroonga/releases/download/4.1.0/pgroonga-4.1.0-postgresql-14-x64.zip";
            row["licenseUrl"] = "https://github.com/pgroonga/pgroonga/blob/4.1.0/COPYING";
        });
        var selectedPgroonga = ExternalSignedDirectGetAdmission.ParseUntrusted(
            pgroongaOriginal, "14", DateTimeOffset.UtcNow, out _, "pgroonga", "4.1.0");
        check(selectedPgroonga.Count == 1 && selectedPgroonga[0].AssetId == 623766852L,
            "Exactly signed PGroonga -postgresql-MAJOR- original can be selected by --version");
        check(ParseDenied(pgroongaOriginal, "14", "pgroonga", "4.1.1"),
            "PGroonga partial/wrong version denied");
        check(ParseDenied(pgroongaOriginal, "18", "pgroonga", "4.1.0"),
            "PGroonga wrong major denied instead of selecting PG14");
        check(ParseDenied(pgroongaOriginal, "14", "pg_trickle", "4.1.0"),
            "PGroonga version cannot be selected for another extension");
        check(ParseDenied(pgroongaOriginal, "14", null, "4.1.0"),
            "PGroonga version pin still requires exact extension");
        var forgedPgroonga = JsonNode.Parse(Encoding.UTF8.GetString(pgroongaOriginal))!;
        forgedPgroonga["records"]![0]!["mirrorAuthorized"] = true;
        check(ParseDenied(Encoding.UTF8.GetBytes(forgedPgroonga.ToJsonString()),
            "14", "pgroonga", "4.1.0"),
            "New PGroonga filename pattern cannot conceal a disallowed source row");

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
            ("forged original provider", "sourceRepo", "laurenz/oracle_fdw"),
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
        check(ParseDenied(mixed, "16", "vector", "0.8.0"),
            "A provider filename without upstream version cannot impersonate a signed version pin");
        check(ExternalSignedDirectGetAdmission.ParseUntrusted(
            mixed, "all", DateTimeOffset.UtcNow, out _, "pg_trickle", "0.108.3").Count == 1,
            "Exact-version filtering across majors retains only the requested signed extension");
        var hiddenVersionBad = JsonNode.Parse(Encoding.UTF8.GetString(mixed))!;
        hiddenVersionBad["records"]![1]!["mirrorAuthorized"] = true;
        check(ParseDenied(Encoding.UTF8.GetBytes(hiddenVersionBad.ToJsonString()),
            "18", "pg_trickle", "0.108.3"),
            "Version filter must not hide an invalid unselected signed source");

        var newlyReviewed = JsonNode.Parse(Encoding.UTF8.GetString(Fixture()))!;
        var reviewed = newlyReviewed["records"]![0]!;
        reviewed["extension"] = "oracle_fdw";
        reviewed["sourceRepo"] = "laurenz/oracle_fdw";
        reviewed["repositoryId"] = 14332609L;
        reviewed["releaseTag"] = "ORACLE_FDW_2_9_0";
        reviewed["releaseId"] = 335861225L;
        reviewed["assetName"] = "oracle_fdw-2.9.0-pg18-win64.zip";
        reviewed["assetId"] = 442625860L;
        reviewed["originalBytes"] = 365101L;
        reviewed["originalSha256"] = "ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678";
        reviewed["originalProviderUrl"] = "https://github.com/laurenz/oracle_fdw/releases/download/ORACLE_FDW_2_9_0/oracle_fdw-2.9.0-pg18-win64.zip";
        check(ExternalSignedDirectGetAdmission.ParseUntrusted(
            Encoding.UTF8.GetBytes(newlyReviewed.ToJsonString()), "18",
            DateTimeOffset.UtcNow, out _).Count == 1,
            "Reviewed PG18 provider structure can be parsed pending real Sigstore proof");
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
