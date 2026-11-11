"""Offline/hostile tests: all outputs are untrusted, nonpublishing reviews."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from issue112_external_batch_plan import INPUTS, PROVIDERS, Denied
from issue112_latest_external_review import make_plan, version_key, DENY


class LatestExternalReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "external").mkdir()
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


if __name__ == "__main__":
    unittest.main()
