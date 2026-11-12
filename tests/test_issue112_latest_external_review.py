"""Offline/hostile tests: all outputs are untrusted, nonpublishing reviews."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from issue112_external_batch_plan import INPUTS, PROVIDERS, Denied
from issue112_latest_external_review import (
    make_plan, version_key, DENY, PGROONGA_PINS, HTTP_PINS,
)
from unittest.mock import patch
from issue112_cybertec_windows_index import BASE as CYBERTEC_BASE, collect, parse_index


class LatestExternalReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "external").mkdir()
        self.timescale_path = (
            self.root / "external/timescaledb-release-watch-baseline-v1.json")
        self.timescale_path.write_text(
            (Path(__file__).resolve().parents[1] /
             "external/timescaledb-release-watch-baseline-v1.json").read_text(
                 encoding="utf-8"), encoding="utf-8")
        self.timescale_rights_path = (
            self.root / "external/timescaledb-rights-provenance-intake-v1.json")
        self.timescale_rights_path.write_text(
            (Path(__file__).resolve().parents[1] /
             "external/timescaledb-rights-provenance-intake-v1.json").read_text(
                 encoding="utf-8"), encoding="utf-8")
        self.providers = {
            "schemaVersion": "pgextwin-external-discovery-providers/v1",
            "trust": "READ_ONLY_METADATA_NEVER_AUTHORIZE",
            "githubApiHost": "api.github.com",
            "providers": [{"repo": "HypoPG/hypopg",
                           "providerType": "upstream-official",
                           "extension": "hypopg",
                           "assetPattern": "^hypopg.*\\\\.zip$"}],
        }
        self.row = {
            "sourceRepo": "HypoPG/hypopg",
            "providerType": "upstream-official",
            "extension": "hypopg", "pgMajor": "16",
            "upstreamVersion": "1.4.1",
            "releaseTag": "1.4.1", "releaseId": 153113229,
            "assetId": 164673171,
            "assetName": "hypopg-1.4.1-pg16-x64.zip",
            "apiDigest": None, "originalSha256": None,
            "originalBytes": None, "downloadAuthorized": False,
            "redistributionAuthorization": "not-authorized",
            "historical": True,
        }
        self.inputs = [{
            "schemaVersion": "pgextwin-windows-source-candidates/v1",
            "trust": "UNVERIFIED_METADATA_ONLY",
            "publicationAuthorized": False, "redistributionAuthorized": False,
            "candidates": [],
        } for _ in INPUTS]
        self.inputs[0]["candidates"] = [self.row]
        self.save()

    def save(self):
        (self.root / PROVIDERS).write_text(json.dumps(self.providers))
        for file, document in zip(INPUTS, self.inputs):
            (self.root / file).write_text(json.dumps(document))

    def test_semver_numeric_order_and_prerelease_ignored(self):
        self.assertGreater(version_key("1.10.0"), version_key("1.9.0"))
        self.assertEqual(version_key("3.7"), version_key("3.7.0"))
        self.assertIsNone(version_key("3.8.0-rc1"))
        self.assertIsNone(version_key("REL_1_4"))
        self.assertIsNone(version_key("9" * 40))

    def test_latest_per_pg_no_cross_major_substitution(self):
        newer = copy.deepcopy(self.row)
        newer.update(upstreamVersion="1.10.0",
                     releaseTag="1.10.0", releaseId=153113230,
                     assetId=164673172, assetName="hypopg-1.10.0-pg16-x64.zip",
                     historical=False)
        other_major = copy.deepcopy(self.row)
        other_major.update(pgMajor="18", assetId=164673173,
                           assetName="hypopg-1.4.1-pg18-x64.zip")
        self.inputs[0]["candidates"].extend((newer, other_major))
        self.save()
        report = make_plan(self.root, source="github")
        rows = report["selected"]
        self.assertEqual({(r["pgMajor"], r["version"]) for r in rows},
                         {("16", "1.10.0"), ("18", "1.4.1")})
        self.assertEqual(report["observedMajorCoverageNotSupportClaim"],
                         {"hypopg": ["16", "18"]})
        self.assertEqual(report["admittedAssets"], 0)

    def test_exact_version_across_all_majors(self):
        row = copy.deepcopy(self.row)
        row.update(pgMajor="18", assetId=100, assetName="hypopg-pg18.zip")
        self.inputs[0]["candidates"].append(row)
        self.save()
        selected = make_plan(self.root, extension="hypopg",
                             version="1.4.1", source="github")
        self.assertEqual(len(selected["selected"]), 2)
        self.assertEqual(make_plan(self.root, "18", "hypopg",
                                   "1.4.1", "github")["selectedReviewRows"], 1)
        self.assertEqual(make_plan(self.root, "18", "hypopg",
                                   "1.4.2", "github")["selectedReviewRows"], 0)

    def test_postgis_pgrouting_one_original_per_major(self):
        result = make_plan(self.root, source="osgeo")
        self.assertEqual(result["selectedReviewRows"], 35)
        self.assertEqual(result["uniqueOriginalPackages"], 5)
        majors = ["14", "15", "16", "17", "18"]
        self.assertEqual(result["observedMajorCoverageNotSupportClaim"],
                         {name: majors for name in (
                             "address_standardizer", "pgrouting", "postgis",
                             "postgis_raster", "postgis_sfcgal",
                             "postgis_tiger_geocoder", "postgis_topology")})
        self.assertTrue(all(row["versionMeaning"] ==
                            "POSTGIS_BUNDLE_VERSION_NOT_COMPONENT_VERSION"
                            for row in result["selected"]))
        self.assertTrue(all(row["blockers"] for row in result["selected"]))
        self.assertEqual(make_plan(self.root, "18", "pgrouting",
                                   "3.7.0", "osgeo")["uniqueOriginalPackages"], 1)
        self.assertEqual(make_plan(self.root, "18", "pgrouting",
                                   "4.0.1", "osgeo")["selectedReviewRows"], 0)

    def test_postgis_subextensions_share_exact_original_no_public_admission(self):
        for major in ("14", "15", "16", "17", "18"):
            result = make_plan(self.root, pg=major, source="osgeo")
            self.assertEqual(result["selectedReviewRows"], 7)
            self.assertEqual(result["uniqueOriginalPackages"], 1)
            self.assertEqual({row["extension"] for row in result["selected"]},
                             {"postgis", "pgrouting", "postgis_raster",
                              "postgis_sfcgal", "postgis_topology",
                              "address_standardizer", "postgis_tiger_geocoder"})
            self.assertEqual(
                {row["packageIdentity"] for row in result["selected"]},
                set(result["uniqueOriginalPackageIdentities"]))
            self.assertTrue(all(row["downloadAuthorized"] is False
                                and row["publisherAuthorized"] is False
                                and row["independentSignedAdmission"] is False
                                and row["blockers"]
                                for row in result["selected"]))
        single = make_plan(self.root, pg="18", extension="postgis_raster",
                           source="osgeo")
        self.assertEqual(single["selectedReviewRows"], 1)
        self.assertEqual(single["uniqueOriginalPackages"], 1)
        self.assertEqual(single["admittedAssets"], 0)

    def test_pgroonga_and_http_reuse_exact_major_pins_without_public_admission(self):
        majors = ["14", "15", "16", "17", "18"]
        for name, source, pins in (("pgroonga", "pgroonga", PGROONGA_PINS),
                                   ("http", "http", HTTP_PINS)):
            report = make_plan(self.root, source=source)
            self.assertEqual(report["selectedReviewRows"], 5)
            self.assertEqual(report["uniqueOriginalPackages"], 5)
            self.assertEqual(report["observedMajorCoverageNotSupportClaim"], {name: majors})
            self.assertFalse(report["latestUpstreamVerified"])
            self.assertEqual(report["admittedAssets"], 0)
            for row in report["selected"]:
                key = int(row["pgMajor"]) if name == "pgroonga" else row["pgMajor"]
                self.assertEqual((row["originalBytes"], row["originalSha256"]), pins[key])
                self.assertTrue(row["blockers"])
                for flag in DENY:
                    self.assertIs(row[flag], False)
        self.assertEqual(make_plan(self.root, source="pgroonga", extension="pgroonga",
                                   version="4.1.0")["selectedReviewRows"], 5)
        self.assertEqual(make_plan(self.root, source="http", extension="http",
                                   version="1.7.1")["observedMajorCoverageNotSupportClaim"],
                         {"http": ["17", "18"]})
        self.assertEqual(make_plan(self.root, pg="16", source="http", extension="http",
                                   version="1.7.1")["selectedReviewRows"], 0)
        self.assertIn("pgroonga", make_plan(self.root)["observedMajorCoverageNotSupportClaim"])
        self.assertIn("http", make_plan(self.root)["observedMajorCoverageNotSupportClaim"])

    def test_new_source_pins_are_fail_closed_even_on_filtered_request(self):
        with patch.dict(PGROONGA_PINS, {18: (0, "0" * 64)}):
            with self.assertRaises(Denied):
                make_plan(self.root, source="pgroonga", pg="14")
        with patch.dict(HTTP_PINS, {"18": (1, "not-sha256")}):
            with self.assertRaises(Denied):
                make_plan(self.root, source="http", pg="14")
        self.assertEqual(make_plan(self.root, source="pgroonga",
                                   extension="http")["selectedReviewRows"], 0)

    def test_timescaledb_independently_rehashed_three_major_selection_not_get(self):
        report = make_plan(self.root, source="timescaledb")
        self.assertEqual(report["selectedReviewRows"], 3)
        self.assertEqual(report["uniqueOriginalPackages"], 3)
        self.assertEqual(report["observedMajorCoverageNotSupportClaim"],
                         {"timescaledb": ["16", "17", "18"]})
        self.assertFalse(report["latestUpstreamVerified"])
        self.assertEqual(report["admittedAssets"], 0)
        for row in report["selected"]:
            self.assertEqual(row["version"], "2.31.0")
            self.assertEqual(row["source"],
                             "TIMESCALEDB_REHASHED_ORIGINAL_ONLY")
            self.assertEqual(row["originalRehashEvidenceRunId"], 43116446694)
            self.assertEqual(row["originalBytes"], row["apiObservedBytes"])
            self.assertEqual(row["originalSha256"], row["apiObservedSha256"])
            self.assertNotIn("INDEPENDENT_ORIGINAL_BYTES_NOT_REHASHED",
                             row["blockers"])
            self.assertIn("SOURCE_TO_BINARY_PRODUCER_ATTESTATION_MISSING",
                          row["blockers"])
            for flag in DENY:
                self.assertIs(row[flag], False)
        selected = make_plan(self.root, pg="17", source="timescaledb",
                             extension="timescaledb", version="2.31.0")
        self.assertEqual(selected["selectedReviewRows"], 1)
        self.assertEqual(selected["uniqueOriginalPackages"], 1)
        self.assertEqual(make_plan(self.root, pg="14",
                                   source="timescaledb")["selectedReviewRows"], 0)
        self.assertEqual(make_plan(self.root, source="timescaledb",
                                   extension="timescaledb",
                                   version="2.32.0")["selectedReviewRows"], 0)
        self.assertIn("timescaledb",
                      make_plan(self.root)["observedMajorCoverageNotSupportClaim"])

    def test_timescaledb_baseline_poison_rejected_even_when_source_filtered(self):
        baseline = json.loads(self.timescale_path.read_text("utf-8"))
        tampered = copy.deepcopy(baseline)
        tampered["downloadAuthorized"] = True
        self.timescale_path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaises(Denied):
            make_plan(self.root, source="osgeo")
        tampered = copy.deepcopy(baseline)
        tampered["records"][1]["assetId"] = tampered["records"][0]["assetId"]
        self.timescale_path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaises(Denied):
            make_plan(self.root, source="github")
        tampered = copy.deepcopy(baseline)
        tampered["records"][0]["assetName"] = "timescaledb-pg16-bad.zip"
        self.timescale_path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaises(Denied):
            make_plan(self.root, source="pgroonga")
        self.timescale_path.write_text(
            '{"trust":"DENY","trust":"ALLOW"}', encoding="utf-8")
        with self.assertRaises(Denied):
            make_plan(self.root, source="timescaledb")
        self.timescale_path.unlink()
        with self.assertRaises(Denied):
            make_plan(self.root, source="http")

    def test_timescaledb_rights_intake_poison_denied_even_when_unselected(self):
        original = json.loads(self.timescale_rights_path.read_text("utf-8"))
        for mutate in (
            lambda x: x["windowsAssets"][0].update(originalBytes=953740),
            lambda x: x["windowsAssets"][1].update(originalSha256="0" * 64),
            lambda x: x["permissions"].update(publicGet=True),
            lambda x: x["evidence"].update(
                upstreamReleaseSourceToBinaryProvenance="PASS"),
            lambda x: x["originalZipInventory"].update(runId=43116446695),
        ):
            poisoned = copy.deepcopy(original)
            mutate(poisoned)
            self.timescale_rights_path.write_text(
                json.dumps(poisoned), encoding="utf-8")
            with self.assertRaises(Denied):
                make_plan(self.root, source="osgeo", pg="14")
        self.timescale_rights_path.write_text(
            '{ "scope": "CANDIDATE_ONLY", "scope": "PUBLIC_COMPLETE" }',
            encoding="utf-8")
        with self.assertRaises(Denied):
            make_plan(self.root, source="github", pg="16")
        self.timescale_rights_path.unlink()
        with self.assertRaises(Denied):
            make_plan(self.root, source="timescaledb")

    def test_no_promotion_and_no_implicit_fallback(self):
        result = make_plan(self.root)
        self.assertFalse(result["latestUpstreamVerified"])
        self.assertEqual(result["admittedAssets"], 0)
        for field in DENY:
            self.assertIs(result[field], False)
        for row in result["selected"]:
            for field in DENY:
                self.assertIs(row[field], False)
        self.assertIn("INDEPENDENT_ORIGINAL_BYTES_NOT_PINNED",
                      next(row for row in result["selected"]
                           if row["extension"] == "hypopg")["blockers"])
        self.assertEqual(make_plan(self.root, "14", "hypopg",
                                   source="github")["selectedReviewRows"], 0)

    def test_invalid_selector_and_unselected_poison_denied(self):
        for kwargs in ({"pg": "19"}, {"extension": "../etc"},
                       {"version": "1.4.1"}, {"extension": "hypopg",
                                               "version": "1.4.*"},
                       {"source": "unapproved"}):
            with self.assertRaises(Denied):
                make_plan(self.root, **kwargs)
        self.row["downloadAuthorized"] = True
        self.save()
        # Even OSGeo-only selection MUST validate all untrusted registry rows.
        with self.assertRaises(Denied):
            make_plan(self.root, source="osgeo")
        self.row["downloadAuthorized"] = False
        self.inputs[0]["publicationAuthorized"] = True
        self.save()
        with self.assertRaises(Denied):
            make_plan(self.root, extension="postgis")

    def test_reuses_existing_p3_holds(self):
        held = copy.deepcopy(self.row)
        held.update(sourceRepo="laurenz/oracle_fdw",
                    providerType="upstream-official", extension="oracle_fdw",
                    assetId=900, assetName="oracle_fdw-pg16.zip")
        self.providers["providers"].append({
            "repo": "laurenz/oracle_fdw",
            "providerType": "upstream-official",
            "extension": "oracle_fdw",
            "assetPattern": "^oracle_fdw.*\\\\.zip$"})
        self.inputs[0]["candidates"].append(held)
        self.save()
        item = make_plan(self.root, source="github",
                         extension="oracle_fdw")["selected"][0]
        self.assertIn("EXISTING_P3_HOLD", item["blockers"])
        self.assertIs(item["downloadAuthorized"], False)


    def cybertec_index(self):
        def listing(*names):
            return ("<a href='../'>../</a>" + "".join(
                f"<a href='{name}'>{name}</a>" for name in names)).encode()
        receipt = collect({
            "16": parse_index(listing(
                "pg_partman-16-public-v5.4.2-1.zip",
                "pg_partman-16-public-v5.4.3-1.zip",
                "orafce-16-public-VERSION_4_16_5-1.zip"), "16"),
            "17": parse_index(listing(
                "pg_partman-17-public-v5.4.3-1.zip",
                "pg_hint_plan-17-17-public-REL17_1_7_1-5-gd06add-1.zip"), "17"),
        })
        path = self.root / "cybertec-index.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        return path, receipt

    def test_cybertec_explicit_index_reuses_canonical_latest_labels_only(self):
        path, _ = self.cybertec_index()
        with self.assertRaises(Denied):
            make_plan(self.root, source="cybertec")
        report = make_plan(self.root, source="cybertec", cybertec_index=path)
        self.assertEqual(report["cybertecSelectedReviewRows"], 4)
        self.assertEqual(report["uniqueOriginalPackages"], 4)
        self.assertEqual(report["admittedAssets"], 0)
        self.assertEqual(report["observedMajorCoverageNotSupportClaim"],
                         {"orafce": ["16"], "pg_hint_plan": ["17"],
                          "pg_partman": ["16", "17"]})
        self.assertEqual(report["cybertecUnrankableGroups"], [])
        for row in report["selected"]:
            self.assertEqual(row["source"], "CYBERTEC_PGEE_DIRECTORY_METADATA_ONLY")
            self.assertIsNone(row["version"])
            self.assertIsNone(row["originalBytes"])
            self.assertIsNone(row["originalSha256"])
            self.assertEqual(row["versionMeaning"],
                             "PROVIDER_PACKAGING_LABEL_NOT_UPSTREAM_VERSION")
            self.assertTrue(row["originalUrlUntrusted"].startswith(CYBERTEC_BASE))
            self.assertIn("COMMUNITY_POSTGRESQL_ABI_UNVERIFIED", row["blockers"])
            for flag in DENY:
                self.assertIs(row[flag], False)
        scoped = make_plan(self.root, pg="16", extension="pg_partman",
                           source="cybertec", cybertec_index=path)
        self.assertEqual([x["providerPackagingLabel"] for x in scoped["selected"]],
                         ["v5.4.3-1"])

    def test_cybertec_exact_packaging_label_is_not_cli_version(self):
        path, _ = self.cybertec_index()
        exact = make_plan(self.root, source="cybertec", cybertec_index=path,
                          extension="pg_partman", packaging_label="v5.4.2-1")
        self.assertEqual([(r["pgMajor"], r["providerPackagingLabel"])
                          for r in exact["selected"]], [("16", "v5.4.2-1")])
        self.assertEqual(make_plan(self.root, source="cybertec", cybertec_index=path,
                                   extension="pg_partman",
                                   packaging_label="v9.0.0")["selectedReviewRows"], 0)
        with self.assertRaises(Denied):
            make_plan(self.root, source="cybertec", cybertec_index=path,
                      extension="pg_partman", version="5.4.3")
        with self.assertRaises(Denied):
            make_plan(self.root, source="cybertec", cybertec_index=path,
                      packaging_label="v5.4.3-1")
        # Exact upstream semver never consumes a Cybertec packaging label.
        other = make_plan(self.root, source="all", cybertec_index=path,
                          extension="hypopg", version="1.4.1")
        self.assertEqual(other["cybertecSelectedReviewRows"], 0)
        self.assertEqual(other["selectedReviewRows"], 1)
        self.assertGreater(make_plan(self.root, source="all",
                                     cybertec_index=path)["cybertecSelectedReviewRows"], 0)

    def test_cybertec_unselected_tamper_and_duplicate_json_key_denied(self):
        path, receipt = self.cybertec_index()
        receipt["candidates"][0]["publicGetAuthorized"] = True
        path.write_text(json.dumps(receipt), encoding="utf-8")
        with self.assertRaises(Denied):
            make_plan(self.root, source="github", cybertec_index=path,
                      extension="hypopg", pg="18")
        path.write_text('{"schemaVersion": "good", "schemaVersion": "bad"}',
                        encoding="utf-8")
        with self.assertRaises(Denied):
            make_plan(self.root, source="cybertec", cybertec_index=path)
        path.unlink()
        with self.assertRaises(Denied):
            make_plan(self.root, source="cybertec", cybertec_index=path)

    def test_cybertec_unrankable_label_excluded_with_explicit_gap(self):
        path, receipt = self.cybertec_index()
        entry = next(r for r in receipt["candidates"] if r["extension"] == "orafce")
        entry["providerBuildLabelUntrusted"] = "preview-unknown"
        entry["fileName"] = "orafce-16-public-preview-unknown.zip"
        entry["originalUrlUntrusted"] = CYBERTEC_BASE + "16/extension/" + entry["fileName"]
        path.write_text(json.dumps(receipt), encoding="utf-8")
        report = make_plan(self.root, source="cybertec", cybertec_index=path)
        self.assertEqual(report["cybertecUnrankableGroups"], [
            {"extension": "orafce", "pgMajor": "16",
             "reason": "UNRANKABLE_PROVIDER_LABEL"}])
        self.assertNotIn("orafce", report["observedMajorCoverageNotSupportClaim"])


if __name__ == "__main__":
    unittest.main()
