using System.Collections.ObjectModel;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using PgExtWin.Releases;

internal static class OsgeoSignedAdmissionTests
{
    private static byte[] Fixture()
    {
        var when = DateTimeOffset.UtcNow.AddMinutes(-2)
            .ToString("yyyy-MM-ddTHH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);
        var until = DateTimeOffset.UtcNow.AddHours(6)
            .ToString("yyyy-MM-ddTHH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

        var bundlesByMajor = new Dictionary<string, object>(StringComparer.Ordinal);
        var extensions = new List<object>();

        foreach (var (major, bundle) in OsgeoSignedAdmission.PinnedCandidateBundles
                     .OrderBy(kv => int.Parse(kv.Key, System.Globalization.CultureInfo.InvariantCulture)))
        {
            bundlesByMajor[major] = new
            {
                bundleId = bundle.BundleId,
                pgMajor = bundle.PgMajor,
                bundleVersion = bundle.BundleVersion,
                fileName = bundle.FileName,
                originalBytes = bundle.OriginalBytes,
                originalSha256 = bundle.OriginalSha256,
                originalProviderUrl = bundle.OriginalProviderUrl,
                limits = new
                {
                    maxOriginalBytes = bundle.Limits.MaxOriginalBytes,
                    maxExpandedBytes = bundle.Limits.MaxExpandedBytes
                },
                targetEnvironment = $"EDB PostgreSQL {major} Windows x64",
                licenseUrl = "https://git.osgeo.org/gitea/postgis/postgis/src/tag/3.7.0/LICENSE.TXT",
                noticeTreatment = "Preserve full PostGIS/pgRouting/GEOS/PROJ/GDAL/SFCGAL original NOTICE and LICENSE files; CANDIDATE_ONLY.",
                dependencyTreatment = $"EDB PostgreSQL {major} Windows x64 runtime DLL closure separately audited; no public GET authorized.",
                approvedOperation = OsgeoSignedAdmission.ExpectedApprovedOperation,
                downloadAuthorized = false,
                mirrorAuthorized = false
            };

            extensions.Add(new
            {
                extension = "postgis",
                pgMajor = major,
                extensionVersion = bundle.ExtensionVersions["postgis"],
                bundleId = bundle.BundleId
            });
            extensions.Add(new
            {
                extension = "pgrouting",
                pgMajor = major,
                extensionVersion = bundle.ExtensionVersions["pgrouting"],
                bundleId = bundle.BundleId
            });
        }

        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = OsgeoSignedAdmission.ExpectedSchemaVersion,
            sourceKind = OsgeoSignedAdmission.ExpectedSourceKind,
            issuerRepository = "pgextwin/build",
            issuerCommit = new string('a', 40),
            catalogCommit = new string('b', 40),
            issuerEvent = "workflow_dispatch",
            issuerRunId = 43681311205L,
            issuerRunAttempt = 1,
            ownerActor = "ShutenOishi",
            ownerId = 27071164L,
            publisherEnvironment = "external-direct-provider-publisher",
            publisherAppId = 5609317L,
            admissionScope = OsgeoSignedAdmission.ExpectedAdmissionScope,
            approvedOperation = OsgeoSignedAdmission.ExpectedApprovedOperation,
            issuedAt = when,
            expiresAt = until,
            downloadAuthorized = false,
            mirrorAuthorized = false,
            redistributionAuthorized = false,
            bundlesByMajor,
            extensions
        });
    }

    private static byte[] Mutate(Action<JsonNode> mutate)
    {
        var doc = JsonNode.Parse(Encoding.UTF8.GetString(Fixture()))!;
        mutate(doc);
        return Encoding.UTF8.GetBytes(doc.ToJsonString());
    }

    private static bool Denied(Action action)
    {
        try { action(); return false; }
        catch (Exception ex) when (ex is InvalidDataException or
            JsonException or InvalidOperationException or FormatException or ArgumentException)
        {
            return true;
        }
    }

    private static bool ParseDenied(byte[] json) =>
        Denied(() => _ = OsgeoSignedAdmission.ParseUntrusted(json, DateTimeOffset.UtcNow, out _));

    private static byte[] MakeZip(params (string Name, byte[] Content)[] files)
    {
        using var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, body) in files)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
                using var stream = entry.Open();
                stream.Write(body, 0, body.Length);
            }
        }
        return output.ToArray();
    }

    public static async Task RunAsync(Action<bool, string> check)
    {
        // 1. Verify fixed pinned facts and per-original limit derivation without lifting global 64 MiB cap.
        check(ExternalOriginalZipIntegrity.MaxOriginalBytes == 64L * 1024 * 1024,
            "Global 64 MiB blanket cap for other external routes remains unchanged");

        var expectedPins = new (string Major, string File, long Bytes, string Sha256)[]
        {
            ("16", "postgis-bundle-pg16-3.7.0x64.zip", 84_037_123L,
                "9fd299d661a049833a84584afd2aaea955e189a4d107b9bf579b56ce154d9eb0"),
            ("17", "postgis-bundle-pg17-3.7.0x64.zip", 84_044_726L,
                "eceb7ed45276db6c9f8757e65ccf8d0ceedaebdcd0c401d442371ce8def61450"),
            ("18", "postgis-bundle-pg18-3.7.0x64.zip", 83_739_256L,
                "ac9e9486b3f9161ad86aea948c99b34ca67438f59263f91d2bcb961b51c7a419")
        };
        check(OsgeoSignedAdmission.PinnedCandidateBundles.Count == 3,
            "Pinned OSGeo candidate cohort covers exactly PG16, PG17 and PG18");
        foreach (var (major, file, bytes, sha) in expectedPins)
        {
            var pin = OsgeoSignedAdmission.PinnedCandidateBundles[major];
            check(pin.PgMajor == major &&
                  pin.FileName == file &&
                  pin.OriginalBytes == bytes &&
                  pin.OriginalSha256 == sha &&
                  pin.Limits.MaxOriginalBytes == bytes &&
                  pin.Limits.MaxExpandedBytes == bytes * OsgeoSignedAdmission.ExpandedLimitMultiplier &&
                  pin.Limits.MaxOriginalBytes > ExternalOriginalZipIntegrity.MaxOriginalBytes &&
                  pin.ExtensionVersions["postgis"] == "3.7.0" &&
                  pin.ExtensionVersions["pgrouting"] == "4.0.1",
                $"OSGeo PG{major} pin carries exact byte/SHA256, per-original limits, and 3.7.0/4.0.1 versions");
        }

        // 2. Parse synthetic OSGeo admission and verify CANDIDATE_ONLY / GET_DENY + dedup.
        var admissionBytes = Fixture();
        var admission = OsgeoSignedAdmission.ParseUntrusted(
            admissionBytes, DateTimeOffset.UtcNow, out var issuerCommit);
        check(issuerCommit == new string('a', 40) &&
              admission.AdmissionScope == "CANDIDATE_ONLY" &&
              admission.ApprovedOperation == "CANDIDATE_ONLY_GET_DENY" &&
              !admission.DownloadAuthorized &&
              !admission.MirrorAuthorized &&
              !admission.RedistributionAuthorized &&
              admission.BundlesByMajor.Count == 3 &&
              admission.Extensions.Count == 6,
            "OSGeo signed admission model parses PG16-18 cohort with CANDIDATE_ONLY / GET_DENY semantics");

        // Same-bundle dedup: PostGIS and pgRouting reference the exact same physical original instance.
        foreach (var major in new[] { "16", "17", "18" })
        {
            var bundle = OsgeoSignedAdmission.GetBundleForMajor(admission, major);
            var postgis = OsgeoSignedAdmission.GetExtensionPin(admission, "postgis", major);
            var pgrouting = OsgeoSignedAdmission.GetExtensionPin(admission, "pgrouting", major);
            check(ReferenceEquals(postgis.Bundle, bundle) &&
                  ReferenceEquals(pgrouting.Bundle, bundle) &&
                  postgis.ExtensionVersion == "3.7.0" &&
                  pgrouting.ExtensionVersion == "4.0.1",
                $"PG{major} postgis (3.7.0) and pgrouting (4.0.1) reference one physical bundle instance");
        }

        var pg18Unique = OsgeoSignedAdmission.SelectUniqueOriginals(admission, "18");
        check(pg18Unique.Count == 1 && pg18Unique[0].OriginalBytes == 83_739_256L,
            "Selecting PG18 without extension filter deduplicates PostGIS+pgRouting to 1 physical original");
        var allUnique = OsgeoSignedAdmission.SelectUniqueOriginals(admission, "all");
        check(allUnique.Count == 3 &&
              allUnique.Select(x => x.PgMajor).SequenceEqual(new[] { "16", "17", "18" }),
            "Selecting all majors deduplicates 6 extension rows to 3 physical originals");
        var pgroutingByVersion = OsgeoSignedAdmission.SelectUniqueOriginals(
            admission, "18", "pgrouting", "4.0.1");
        var postgisByVersion = OsgeoSignedAdmission.SelectUniqueOriginals(
            admission, "18", "postgis", "3.7.0");
        check(pgroutingByVersion.Count == 1 &&
              postgisByVersion.Count == 1 &&
              ReferenceEquals(pgroutingByVersion[0], postgisByVersion[0]),
            "Selecting pgrouting 4.0.1 and postgis 3.7.0 on PG18 resolves to the same physical original");

        // Reject pgRouting 4.0.2 (website description) and 3.7.0 (bundle version).
        check(Denied(() => OsgeoSignedAdmission.SelectUniqueOriginals(admission, "18", "pgrouting", "4.0.2")),
            "pgRouting rejects unpinned description version 4.0.2");
        check(Denied(() => OsgeoSignedAdmission.SelectUniqueOriginals(admission, "18", "pgrouting", "3.7.0")),
            "pgRouting rejects bundle version 3.7.0 as extensionVersion");

        // 3. Fail-closed checks: unknown major, missing pin, absent/mismatched per-original limits.
        check(Denied(() => OsgeoSignedAdmission.GetBundleForMajor(admission, "19")),
            "Unknown PG major 19 rejected");
        check(Denied(() => OsgeoSignedAdmission.GetBundleForMajor(admission, "14")),
            "Absent PG14 bundle pin rejected");
        check(Denied(() => OsgeoSignedAdmission.SelectUniqueOriginals(admission, "15")),
            "Absent PG15 bundle selection fails closed");
        check(Denied(() => OsgeoSignedAdmission.SelectUniqueOriginals(admission, "18", "pg_sphere")),
            "Unsupported/unadmitted OSGeo extension rejected");
        check(Denied(() => OsgeoSignedAdmission.SelectUniqueOriginals(admission, "18", null, "3.7.0")),
            "Version without extension rejected");

        // Absent or inconsistent per-original limits must fail closed.
        check(ParseDenied(Mutate(doc => ((JsonObject)doc["bundlesByMajor"]!["18"]!).Remove("limits"))),
            "Admission with absent per-original limits rejected");
        check(ParseDenied(Mutate(doc => doc["bundlesByMajor"]!["18"]!["limits"] = null)),
            "Admission with null per-original limits rejected");
        check(ParseDenied(Mutate(doc => ((JsonObject)doc["bundlesByMajor"]!["18"]!["limits"]!).Remove("maxExpandedBytes"))),
            "Admission missing maxExpandedBytes rejected");
        check(ParseDenied(Mutate(doc => ((JsonObject)doc["bundlesByMajor"]!["18"]!["limits"]!).Remove("maxOriginalBytes"))),
            "Admission missing maxOriginalBytes rejected");
        check(ParseDenied(Mutate(doc => doc["bundlesByMajor"]!["18"]!["limits"]!["maxOriginalBytes"] = 83_739_257L)),
            "Per-original maxOriginalBytes exceeding pin rejected");
        check(ParseDenied(Mutate(doc => doc["bundlesByMajor"]!["18"]!["limits"]!["maxExpandedBytes"] = 100L)),
            "Inconsistent per-original maxExpandedBytes rejected");
        check(ParseDenied(Mutate(doc => doc["bundlesByMajor"]!["18"]!["limits"]!["extra"] = 1)),
            "Unknown field in per-original limits rejected");

        var pg18Pin = OsgeoSignedAdmission.GetBundleForMajor(admission, "18");
        check(Denied(() => OsgeoSignedAdmission.ValidateBundle(pg18Pin with { Limits = null! })),
            "C# record validation rejects null Limits");
        check(Denied(() => OsgeoSignedAdmission.ValidateBundle(
            pg18Pin with { Limits = new OsgeoOriginalLimits(pg18Pin.OriginalBytes + 1, pg18Pin.Limits.MaxExpandedBytes) })),
            "C# record validation rejects Limits not derived from pin");

        // Unknown major / missing pin / duplicate bundle / size-SHA mismatch in JSON.
        check(ParseDenied(Mutate(doc => ((JsonObject)doc["bundlesByMajor"]!).Add("19", doc["bundlesByMajor"]!["18"]!.DeepClone()))),
            "Unknown major 19 in bundlesByMajor rejected");
        check(ParseDenied(Mutate(doc => ((JsonObject)doc["bundlesByMajor"]!).Remove("18"))),
            "Missing bundle pin referenced by extensions rejected");
        check(ParseDenied(Mutate(doc => ((JsonArray)doc["extensions"]!).RemoveAt(5))),
            "Missing pgrouting extension reference rejected");
        check(ParseDenied(Mutate(doc =>
            doc["bundlesByMajor"]!["17"]!["originalSha256"] = doc["bundlesByMajor"]!["18"]!["originalSha256"]!.GetValue<string>())),
            "Duplicate physical bundle SHA256 across majors rejected");
        check(ParseDenied(Mutate(doc =>
            ((JsonArray)doc["extensions"]!).Add(doc["extensions"]![0]!.DeepClone()))),
            "Duplicate extension entry for same PG major rejected");
        check(ParseDenied(Mutate(doc => doc["extensions"]![0]!["bundleId"] = "other-bundle-id")),
            "Mismatched bundleId between extension and physical bundle rejected");
        check(ParseDenied(Mutate(doc => doc["bundlesByMajor"]!["18"]!["originalBytes"] = 83_739_255L)),
            "Pin byte size mismatch against limits rejected");
        check(ParseDenied(Mutate(doc => doc["bundlesByMajor"]!["18"]!["originalSha256"] = new string('A', 64))),
            "Uppercase SHA256 rejected");
        check(ParseDenied(Mutate(doc => doc["bundlesByMajor"]!["18"]!["originalSha256"] = "bad")),
            "Invalid SHA256 rejected");
        check(ParseDenied(Mutate(doc => doc["bundlesByMajor"]!["18"]!["originalProviderUrl"] =
            "https://github.com/postgis/postgis/releases/download/3.7.0/postgis-bundle-pg18-3.7.0x64.zip")),
            "Off-origin provider URL rejected");

        // Permission escalation must fail closed (semantics stay CANDIDATE_ONLY / GET_DENY).
        foreach (var (name, mutate) in new (string, Action<JsonNode>)[]
        {
            ("root downloadAuthorized=true", doc => doc["downloadAuthorized"] = true),
            ("root mirrorAuthorized=true", doc => doc["mirrorAuthorized"] = true),
            ("root redistributionAuthorized=true", doc => doc["redistributionAuthorized"] = true),
            ("root approvedOperation=ORIGINAL_PROVIDER_GET_ONLY", doc => doc["approvedOperation"] = "ORIGINAL_PROVIDER_GET_ONLY"),
            ("root admissionScope=PUBLIC_GET", doc => doc["admissionScope"] = "PUBLIC_GET"),
            ("bundle downloadAuthorized=true", doc => doc["bundlesByMajor"]!["18"]!["downloadAuthorized"] = true),
            ("bundle mirrorAuthorized=true", doc => doc["bundlesByMajor"]!["18"]!["mirrorAuthorized"] = true),
            ("bundle approvedOperation=ORIGINAL_PROVIDER_GET_ONLY", doc => doc["bundlesByMajor"]!["18"]!["approvedOperation"] = "ORIGINAL_PROVIDER_GET_ONLY"),
            ("wrong ownerActor", doc => doc["ownerActor"] = "impostor"),
            ("wrong ownerId", doc => doc["ownerId"] = 1),
            ("wrong issuerRepository", doc => doc["issuerRepository"] = "pgextwin/catalog"),
            ("wrong sourceKind", doc => doc["sourceKind"] = "EXTERNAL_GITHUB_RELEASE_ASSET"),
            ("expired admission", doc => doc["expiresAt"] = "2020-01-01T00:00:00Z"),
            ("unknown root field", doc => doc["extra"] = true),
            ("unknown bundle field", doc => doc["bundlesByMajor"]!["18"]!["extra"] = true),
            ("unknown extension field", doc => doc["extensions"]![0]!["extra"] = true)
        })
        {
            check(ParseDenied(Mutate(mutate)), $"OSGeo admission rejects {name}");
        }

        // Duplicate JSON keys fail closed via StrictJson.
        var dupJson = Encoding.UTF8.GetBytes(
            Encoding.UTF8.GetString(admissionBytes).Replace(
                "\"downloadAuthorized\":false",
                "\"downloadAuthorized\":false,\"downloadAuthorized\":false"));
        check(ParseDenied(dupJson), "Duplicate JSON key in OSGeo admission rejected");

        // 4. Per-original byte/ZIP verification (size, SHA256, and per-original MaxExpandedBytes).
        var validZip = MakeZip(
            ("share/extension/postgis.control", Encoding.UTF8.GetBytes("default_version = '3.7.0'\n")),
            ("share/extension/pgrouting.control", Encoding.UTF8.GetBytes("default_version = '4.0.1'\n")));
        var validBundle = new OsgeoBundleOriginal(
            BundleId: "osgeo-postgis-bundle-pg18-3.7.0",
            PgMajor: "18",
            BundleVersion: "3.7.0",
            FileName: "postgis-bundle-pg18-3.7.0x64.zip",
            OriginalBytes: validZip.LongLength,
            OriginalSha256: Convert.ToHexStringLower(SHA256.HashData(validZip)),
            OriginalProviderUrl: "https://download-cache.osgeo.org/postgis/windows/pg18/postgis-bundle-pg18-3.7.0x64.zip",
            Limits: OsgeoSignedAdmission.DeriveLimits(validZip.LongLength),
            ExtensionVersions: new ReadOnlyDictionary<string, string>(
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["postgis"] = "3.7.0",
                    ["pgrouting"] = "4.0.1"
                }));
        var receipt = OsgeoSignedAdmission.VerifyBundleBytes(validZip, validBundle);
        check(receipt.OriginalBytes == validZip.LongLength &&
              receipt.OriginalSha256 == validBundle.OriginalSha256 &&
              receipt.ArchiveMembers == 2 &&
              receipt.Scope == "CANDIDATE_INTEGRITY_ONLY_NOT_AUTHORIZED",
            "Per-original OSGeo ZIP verification succeeds with CANDIDATE_INTEGRITY_ONLY_NOT_AUTHORIZED scope");

        check(Denied(() => OsgeoSignedAdmission.VerifyBundleBytes(
            validZip, validBundle with { OriginalSha256 = new string('0', 64) })),
            "VerifyBundleBytes rejects SHA256 mismatch");
        check(Denied(() => OsgeoSignedAdmission.VerifyBundleBytes(
            validZip[..^1], validBundle)),
            "VerifyBundleBytes rejects byte length mismatch");
        var corruptedZip = (byte[])validZip.Clone();
        corruptedZip[12] ^= 0x01;
        check(Denied(() => OsgeoSignedAdmission.VerifyBundleBytes(corruptedZip, validBundle)),
            "VerifyBundleBytes rejects corrupted ZIP bytes");

        // Highly compressible zeroes exceeding per-original MaxExpandedBytes (24 * originalBytes).
        var zeroPayload = new byte[64 * 1024];
        var overExpandedZip = MakeZip(("big.bin", zeroPayload));
        var overExpandedBundle = validBundle with
        {
            OriginalBytes = overExpandedZip.LongLength,
            OriginalSha256 = Convert.ToHexStringLower(SHA256.HashData(overExpandedZip)),
            Limits = OsgeoSignedAdmission.DeriveLimits(overExpandedZip.LongLength)
        };
        check(zeroPayload.LongLength > overExpandedBundle.Limits.MaxExpandedBytes &&
              Denied(() => OsgeoSignedAdmission.VerifyBundleBytes(overExpandedZip, overExpandedBundle)),
            "VerifyBundleBytes enforces per-original MaxExpandedBytes derived from pin");

        var traversalZip = MakeZip(("../escape.dll", Encoding.UTF8.GetBytes("bad")));
        var traversalBundle = validBundle with
        {
            OriginalBytes = traversalZip.LongLength,
            OriginalSha256 = Convert.ToHexStringLower(SHA256.HashData(traversalZip)),
            Limits = OsgeoSignedAdmission.DeriveLimits(traversalZip.LongLength)
        };
        check(Denied(() => OsgeoSignedAdmission.VerifyBundleBytes(traversalZip, traversalBundle)),
            "VerifyBundleBytes rejects ZIP path traversal");

        // Shared verifier path/attribute hardening and min(DeriveLimits, profile) enforcement.
        foreach (var (label, entries) in new (string, (string Name, byte[] Content)[])[]
        {
            ("double slash folder//", [("folder//", []), ("ok.txt", "ok"u8.ToArray())]),
            ("parent-child collision a and a/b", [("a", "f"u8.ToArray()), ("a/b", "c"u8.ToArray())]),
            ("reverse parent-child collision a/b and a", [("a/b", "c"u8.ToArray()), ("a", "f"u8.ToArray())]),
            ("Windows reserved name NUL.txt", [("NUL.txt", "bad"u8.ToArray())]),
            ("trailing dot", [("bad.", "bad"u8.ToArray())]),
            ("Unicode normalization difference", [("caf\u00e9.txt", "a"u8.ToArray()), ("cafe\u0301.txt", "b"u8.ToArray())])
        })
        {
            var badZip = MakeZip(entries);
            var badBundle = validBundle with
            {
                OriginalBytes = badZip.LongLength,
                OriginalSha256 = Convert.ToHexStringLower(SHA256.HashData(badZip)),
                Limits = OsgeoSignedAdmission.DeriveLimits(badZip.LongLength)
            };
            check(Denied(() => OsgeoSignedAdmission.VerifyBundleBytes(badZip, badBundle)),
                $"VerifyBundleBytes rejects {label}");
        }

        // Enforce min(DeriveLimits, profile) for single entry and compressed original bounds.
        var mediumPayload = new byte[256];
        Array.Fill(mediumPayload, (byte)'X');
        var mediumZip = MakeZip(("single.bin", mediumPayload));
        var mediumBundle = validBundle with
        {
            OriginalBytes = mediumZip.LongLength,
            OriginalSha256 = Convert.ToHexStringLower(SHA256.HashData(mediumZip)),
            Limits = OsgeoSignedAdmission.DeriveLimits(mediumZip.LongLength)
        };
        var tighterEntryProfile = new OriginalZipResourceProfile(
            MaxCompressedOriginalBytes: 96L * 1024 * 1024,
            MaxEntryUncompressedBytes: 200,
            MaxTotalUncompressedBytes: 2L * 1024 * 1024 * 1024,
            MaxEntries: 25_000);
        check(mediumPayload.LongLength <= mediumBundle.Limits.MaxExpandedBytes &&
              Denied(() => OsgeoSignedAdmission.VerifyBundleBytes(mediumZip, mediumBundle, tighterEntryProfile)),
            "VerifyBundleBytes enforces min(DeriveLimits, profile) for MaxEntryUncompressedBytes");

        var tighterCompressedProfile = new OriginalZipResourceProfile(
            MaxCompressedOriginalBytes: mediumZip.LongLength - 1,
            MaxEntryUncompressedBytes: 96L * 1024 * 1024,
            MaxTotalUncompressedBytes: 2L * 1024 * 1024 * 1024,
            MaxEntries: 25_000);
        check(Denied(() => OsgeoSignedAdmission.VerifyBundleBytes(mediumZip, mediumBundle, tighterCompressedProfile)),
            "VerifyBundleBytes enforces min(DeriveLimits, profile) for MaxCompressedOriginalBytes");

        // PG14 and PG15 (~118 MiB originals) must NOT reuse PG18's 96 MiB profile and fail closed.
        foreach (var unprofiledMajor in new[] { "14", "15" })
        {
            var unprofiledBundle = validBundle with
            {
                BundleId = $"osgeo-postgis-bundle-pg{unprofiledMajor}-3.7.0",
                PgMajor = unprofiledMajor,
                FileName = $"postgis-bundle-pg{unprofiledMajor}-3.7.0x64.zip",
                OriginalProviderUrl = $"https://download-cache.osgeo.org/postgis/windows/pg{unprofiledMajor}/postgis-bundle-pg{unprofiledMajor}-3.7.0x64.zip"
            };
            check(Denied(() => OsgeoSignedAdmission.VerifyBundleBytes(validZip, unprofiledBundle)),
                $"VerifyBundleBytes fails closed for unprofiled PG{unprofiledMajor}");
        }

        // PG16 and PG17 3.7.0 bundles verify with CANDIDATE_INTEGRITY_ONLY_NOT_AUTHORIZED scope.
        foreach (var profiledMajor in new[] { "16", "17" })
        {
            var profiledBundle = validBundle with
            {
                BundleId = $"osgeo-postgis-bundle-pg{profiledMajor}-3.7.0",
                PgMajor = profiledMajor,
                FileName = $"postgis-bundle-pg{profiledMajor}-3.7.0x64.zip",
                OriginalProviderUrl = $"https://download-cache.osgeo.org/postgis/windows/pg{profiledMajor}/postgis-bundle-pg{profiledMajor}-3.7.0x64.zip"
            };
            var r = OsgeoSignedAdmission.VerifyBundleBytes(validZip, profiledBundle);
            check(r.Scope == "CANDIDATE_INTEGRITY_ONLY_NOT_AUTHORIZED" && r.ArchiveMembers == 2,
                $"VerifyBundleBytes verifies PG{profiledMajor} bundle with candidate-only scope");
        }

        // 5. Sigstore gate fails closed for unsigned/empty bundle without network calls.
        var sigstoreRejected = false;
        try
        {
            _ = await OsgeoSignedAdmission.VerifyAsync(admissionBytes, Encoding.UTF8.GetBytes("{}"));
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or
            FormatException or InvalidOperationException)
        {
            sigstoreRejected = true;
        }
        check(sigstoreRejected, "Unsigned local OSGeo admission fails closed in VerifyAsync");
    }
}
