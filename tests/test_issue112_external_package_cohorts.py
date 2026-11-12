"""Nonpublishing original-cohort compiler and adversarial tests."""
import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue112_external_package_cohorts import build, Denied
from issue112_latest_external_review import DENY


def row(extension, ident="osgeo:pg18:3.7.0:digest", pg="18"):
    return {
        "packageIdentity": ident, "source": "OSGEO_REHASHED_ORIGINAL_ONLY",
        "provider": "OSGeo/PostGIS Windows Winnie", "pgMajor": pg,
        "extension": extension, "assetName": "postgis-bundle-pg18-3.7.0x64.zip",
        "format": "zip", "version": "3.7.0",
        "versionMeaning": "POSTGIS_BUNDLE_VERSION_NOT_COMPONENT_VERSION",
        "originalBytes": 83320975, "originalSha256": "a" * 64,
        "blockers": ["SOURCE_TO_BINARY_PRODUCER_ATTESTATION_MISSING"],
        **DENY,
    }


def plan(rows):
    ids = sorted(set(x["packageIdentity"] for x in rows))
    return {
        "schemaVersion": "pgextwin-issue112-latest-external-review/v1",
        "trust": "CANDIDATE_REVIEW_ONLY_NEVER_AUTHORIZATION",
        "selectionRule": "HIGHEST_STABLE_VERSION_OBSERVED_PER_EXTENSION_AND_PG",
        "selected": rows, "selectedReviewRows": len(rows),
        "uniqueOriginalPackages": len(ids),
        "uniqueOriginalPackageIdentities": ids,
        "observedMajorCoverageNotSupportClaim":
            {x["extension"]: [x["pgMajor"]] for x in rows},
        "admittedAssets": 0, **DENY,
    }


class PackageCohortTests(unittest.TestCase):
    def compile(self, fixture, **kwargs):
        with patch("issue112_external_package_cohorts.make_plan",
                   return_value=fixture):
            return build(**kwargs)

    def test_postgis_and_pgrouting_share_exact_one_zip(self):
        out = self.compile(plan([row("postgis"), row("pgrouting")]))
        self.assertEqual(out["selectedReviewRows"], 2)
        self.assertEqual(out["uniqueOriginalPackages"], 1)
        self.assertEqual(out["reviewBatchCount"], 1)
        item = out["batches"][0]["packages"][0]
        self.assertEqual(item["extensions"], ["pgrouting", "postgis"])
        self.assertEqual(item["observedVersion"], "3.7.0")
        self.assertEqual(item["versionMeaning"],
                         "POSTGIS_BUNDLE_VERSION_NOT_COMPONENT_VERSION")
        self.assertTrue(item["sharedBundle"])
        self.assertFalse(item["downloadAuthorized"])
        self.assertEqual(out["networkRequests"], 0)
        self.assertEqual(out["admittedAssets"], 0)

    def test_many_originals_chunk_without_duplication(self):
        rows = []
        for i in range(5):
            r = row("postgis", ident=f"osgeo:{i}")
            r["assetName"] = f"postgis-bundle-pg18-3.7.{i}x64.zip"
            r["version"] = f"3.7.{i}"
            rows.append(r)
        out = self.compile(plan(rows), max_batch=2)
        self.assertEqual([len(b["packages"]) for b in out["batches"]],
                         [2, 2, 1])
        self.assertEqual(out["uniqueOriginalPackages"], 5)

    def test_exact_selection_passed_to_original_checked_selector(self):
        fixture = plan([row("postgis")])
        with patch("issue112_external_package_cohorts.make_plan",
                   return_value=fixture) as mock:
            out = build(pg="18", extension="postgis", version="3.7.0",
                        source="osgeo")
        self.assertEqual(out["exactVersionSelection"], "3.7.0")
        self.assertEqual(mock.call_args.kwargs["version"], "3.7.0")
        self.assertEqual(mock.call_args.kwargs["source"], "osgeo")

    def test_missing_majors_are_not_invented(self):
        out = self.compile(plan([row("postgis")]))
        self.assertEqual(out["unobservedMajorsNotSupportVerdict"]["postgis"],
                         ["14", "15", "16", "17"])

    def test_duplicate_same_extension_rejected(self):
        with self.assertRaises(Denied):
            self.compile(plan([row("postgis"), row("postgis")]))

    def test_same_identity_different_bytes_rejected(self):
        altered = row("pgrouting")
        altered["originalSha256"] = "b" * 64
        with self.assertRaises(Denied):
            self.compile(plan([row("postgis"), altered]))

    def test_same_identity_different_pg_rejected(self):
        altered = row("pgrouting", pg="17")
        with self.assertRaises(Denied):
            self.compile(plan([row("postgis"), altered]))

    def test_forged_permission_row_rejected(self):
        malicious = row("postgis")
        malicious["downloadAuthorized"] = True
        with self.assertRaises(Denied):
            self.compile(plan([malicious]))

    def test_forged_permission_root_rejected(self):
        malicious = plan([row("postgis")])
        malicious["publisherAuthorized"] = True
        with self.assertRaises(Denied):
            self.compile(malicious)

    def test_mismatched_sha_size_rejected(self):
        malicious = row("postgis")
        malicious["originalSha256"] = None
        with self.assertRaises(Denied):
            self.compile(plan([malicious]))

    def test_missing_blockers_rejected(self):
        malicious = row("postgis")
        malicious["blockers"] = []
        with self.assertRaises(Denied):
            self.compile(plan([malicious]))

    def test_mismatched_dedup_cardinality_rejected(self):
        malicious = plan([row("postgis")])
        malicious["uniqueOriginalPackages"] = 2
        with self.assertRaises(Denied):
            self.compile(malicious)

    def test_invalid_batch_bounds_rejected(self):
        for value in (0, 21, True, -3):
            with self.subTest(value=value), self.assertRaises(Denied):
                self.compile(plan([row("postgis")]), max_batch=value)

    def test_unknown_archive_extension_rejected(self):
        malicious = row("postgis")
        malicious["format"] = "tar"
        with self.assertRaises(Denied):
            self.compile(plan([malicious]))

    def test_unpinned_community_candidate_stays_deny(self):
        row1 = row("pgvector", ident="github:one")
        row1.update(source="GITHUB_DISCOVERY_ONLY", provider="community/test",
                    assetName="vector.v0.8.7-pg18.zip", format="zip",
                    version="0.8.7", versionMeaning="UPSTREAM_VERSION_OBSERVED",
                    originalBytes=None, originalSha256=None, sharedBundle=False)
        out = self.compile(plan([row1]))
        self.assertIsNone(out["batches"][0]["packages"][0]["originalSha256"])
        self.assertFalse(out["userDownloadAvailable"])
        self.assertFalse(out["independentSignedAdmission"])


if __name__ == "__main__":
    unittest.main()
