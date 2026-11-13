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
            r = row(f"component_{i}", ident=f"osgeo:{i}")
            r["assetName"] = f"postgis-bundle-pg18-{i}x64.zip"
            rows.append(r)
        out = self.compile(plan(rows), max_batch=2)
        self.assertEqual([len(b["packages"]) for b in out["batches"]],
                         [2, 2, 1])
        self.assertEqual(out["uniqueOriginalPackages"], 5)

    def test_latest_global_version_omits_older_pg_without_fallback(self):
        older = row("hypopg", ident="github:older", pg="16")
        older.update(source="GITHUB_DISCOVERY_ONLY", provider="HypoPG/hypopg",
                     assetName="hypopg-1.4.1-pg16-x64.zip",
                     version="1.4.1", versionMeaning="UPSTREAM_VERSION_OBSERVED")
        latest = row("hypopg", ident="github:newer", pg="18")
        latest.update(source="GITHUB_DISCOVERY_ONLY", provider="HypoPG/hypopg",
                      assetName="hypopg-1.4.5-pg18-x64.zip",
                      version="1.4.5", versionMeaning="UPSTREAM_VERSION_OBSERVED")
        out = self.compile(plan([older, latest]))
        self.assertEqual(out["uniqueOriginalPackages"], 1)
        self.assertEqual(out["olderObservedRowsOmitted"], 1)
        self.assertEqual(out["observedMajorCoverageNotSupportClaim"]["hypopg"],
                         ["18"])
        self.assertIn("16", out["unobservedMajorsNotSupportVerdict"]["hypopg"])
        self.assertFalse(out["userDownloadAvailable"])

    def test_latest_per_pg_keeps_observed_major_versions_without_fallback(self):
        pg16 = row("hypopg", ident="github:pg16", pg="16")
        pg16.update(source="GITHUB_DISCOVERY_ONLY", provider="HypoPG/hypopg",
                    assetName="hypopg-1.4.1-pg16-x64.zip", version="1.4.1",
                    versionMeaning="UPSTREAM_VERSION_OBSERVED")
        pg18 = row("hypopg", ident="github:pg18", pg="18")
        pg18.update(source="GITHUB_DISCOVERY_ONLY", provider="HypoPG/hypopg",
                    assetName="hypopg-1.4.5-pg18-x64.zip", version="1.4.5",
                    versionMeaning="UPSTREAM_VERSION_OBSERVED")
        result = self.compile(plan([pg16, pg18]), latest_per_pg=True)
        self.assertEqual(result["selectionRule"],
                         "LATEST_OBSERVED_PER_EXTENSION_AND_PG")
        self.assertTrue(result["latestPerPgMajorRequested"])
        self.assertEqual(result["uniqueOriginalPackages"], 2)
        self.assertEqual(result["olderObservedRowsOmitted"], 0)
        self.assertEqual(result["observedMajorCoverageNotSupportClaim"]["hypopg"],
                         ["16", "18"])
        self.assertEqual(result["unobservedMajorsNotSupportVerdict"]["hypopg"],
                         ["14", "15", "17"])
        self.assertEqual(result["networkRequests"], 0)
        self.assertFalse(result["downloadAuthorized"])
        self.assertFalse(result["userDownloadAvailable"])
        self.assertTrue(all(not p["downloadAuthorized"] for batch in
                            result["batches"] for p in batch["packages"]))

    def test_latest_per_pg_rejects_exact_version_and_non_boolean(self):
        fixture = plan([row("postgis")])
        for bad in ({"latest_per_pg": True, "version": "3.7.0"},
                    {"latest_per_pg": 1}):
            with self.subTest(bad=bad), self.assertRaises(Denied):
                self.compile(fixture, **bad)

    def test_latest_per_pg_single_bundle_keeps_other_major_candidates(self):
        osgeo17 = row("postgis", ident="osgeo:pg17:3.6.2", pg="17")
        osgeo17.update(assetName="postgis-bundle-pg17-3.6.2x64.zip",
                       version="3.6.2")
        osgeo18 = row("postgis", ident="osgeo:pg18:3.7.0", pg="18")
        pg16 = row("hypopg", ident="github:pg16", pg="16")
        pg16.update(source="GITHUB_DISCOVERY_ONLY", provider="HypoPG/hypopg",
                    assetName="hypopg-1.4.1-pg16-x64.zip", version="1.4.1",
                    versionMeaning="UPSTREAM_VERSION_OBSERVED")
        pg18 = row("hypopg", ident="github:pg18", pg="18")
        pg18.update(source="GITHUB_DISCOVERY_ONLY", provider="HypoPG/hypopg",
                    assetName="hypopg-1.4.5-pg18-x64.zip", version="1.4.5",
                    versionMeaning="UPSTREAM_VERSION_OBSERVED")
        result = self.compile(plan([osgeo17, osgeo18, pg16, pg18]),
                              single_bundle=True, latest_per_pg=True)
        self.assertEqual(result["uniqueOriginalPackages"], 3)
        self.assertEqual(result["singleBundleOriginalIdentity"],
                         "osgeo:pg18:3.7.0")
        self.assertEqual(result["observedMajorCoverageNotSupportClaim"]["hypopg"],
                         ["16", "18"])
        self.assertFalse(result["downloadAuthorized"])

    def test_explicit_version_never_filtered_by_global_latest(self):
        older = row("hypopg", ident="github:older", pg="16")
        older.update(source="GITHUB_DISCOVERY_ONLY", version="1.4.1",
                     versionMeaning="UPSTREAM_VERSION_OBSERVED")
        newer = row("hypopg", ident="github:newer", pg="18")
        newer.update(source="GITHUB_DISCOVERY_ONLY", version="1.4.5",
                     versionMeaning="UPSTREAM_VERSION_OBSERVED")
        out = self.compile(plan([older, newer]), version="1.4.1",
                           extension="hypopg")
        # Patched selector deliberately provides more rows than requested;
        # this layer preserves exact selection ownership in make_plan.
        self.assertEqual(out["olderObservedRowsOmitted"], 0)

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

    def test_real_catalog_osgeo_single_bundle_offline(self):
        # No synthetic source metadata here: exercise the actual protected
        # OSGeo original pin matrix and real latest external selector.
        out = build(source="osgeo", pg="all", single_bundle=True)
        self.assertEqual(out["uniqueOriginalPackages"], 1)
        self.assertEqual(out["reviewBatchCount"], 1)
        self.assertEqual(out["networkRequests"], 0)
        self.assertEqual(out["admittedAssets"], 0)
        self.assertFalse(out["userDownloadAvailable"])
        one = out["batches"][0]["packages"][0]
        self.assertTrue(one["sharedBundle"])
        self.assertEqual(len(one["extensions"]), 14)
        self.assertIn("ogr_fdw", one["extensions"])
        self.assertIn("pg_sphere", one["extensions"])
        self.assertEqual(out["singleBundleOriginalIdentity"], one["packageIdentity"])
        self.assertEqual(out["observedMajorCoverageNotSupportClaim"]["postgis"],
                         [one["pgMajor"]])

    def test_single_newest_observed_osgeo_bundle_retains_other_sources(self):
        older = row("postgis", ident="osgeo:pg17:3.6.2", pg="17")
        older.update(assetName="postgis-bundle-pg17-3.6.2x64.zip", version="3.6.2")
        newer = row("postgis", ident="osgeo:pg18:3.7.0", pg="18")
        routing = row("pgrouting", ident="osgeo:pg18:3.7.0", pg="18")
        other = row("hypopg", ident="github:hypopg", pg="16")
        other.update(source="GITHUB_DISCOVERY_ONLY", provider="HypoPG/hypopg",
                     assetName="hypopg-1.4.1-pg16-x64.zip", version="1.4.1",
                     versionMeaning="UPSTREAM_VERSION_OBSERVED",
                     originalBytes=None, originalSha256=None)
        out = self.compile(plan([older, newer, routing, other]),
                           single_bundle=True)
        packages = [p for b in out["batches"] for p in b["packages"]]
        self.assertEqual(len(packages), 2)
        self.assertEqual({p["pgMajor"] for p in packages}, {"16", "18"})
        bundle = next(p for p in packages if p["sharedBundle"])
        self.assertEqual(bundle["extensions"], ["pgrouting", "postgis"])
        self.assertEqual(bundle["pgMajor"], "18")
        self.assertEqual(out["singleBundleOriginalIdentity"], "osgeo:pg18:3.7.0")
        self.assertTrue(out["singleBundleMajorIsNotCrossMajorCompatibility"])
        self.assertIn("17", out["unobservedMajorsNotSupportVerdict"]["postgis"])
        self.assertFalse(out["downloadAuthorized"])
        self.assertFalse(out["userDownloadAvailable"])

    def test_single_bundle_tie_prefers_higher_observed_pg_major(self):
        pg17 = row("postgis", ident="osgeo:pg17:3.7.0", pg="17")
        pg17["assetName"] = "postgis-bundle-pg17-3.7.0x64.zip"
        pg18 = row("postgis", ident="osgeo:pg18:3.7.0", pg="18")
        out = self.compile(plan([pg17, pg18]), single_bundle=True)
        self.assertEqual(out["singleBundleOriginalIdentity"], "osgeo:pg18:3.7.0")
        self.assertEqual(out["observedMajorCoverageNotSupportClaim"]["postgis"],
                         ["18"])

    def test_single_bundle_requires_all_pg_and_no_exact_version(self):
        fixture = plan([row("postgis")])
        for opts in ({"single_bundle": 1}, {"single_bundle": True, "pg": "18"},
                     {"single_bundle": True, "version": "3.7.0"},
                     {"single_bundle": True, "source": "github"}):
            with self.subTest(opts=opts), self.assertRaises(Denied):
                self.compile(fixture, **opts)

    def test_poisoned_older_row_cannot_be_hidden_by_latest_filter(self):
        older = row("hypopg", ident="github:old", pg="16")
        older.update(source="GITHUB_DISCOVERY_ONLY", provider="HypoPG/hypopg",
                     assetName="hypopg-1.4.1-pg16-x64.zip",
                     versionMeaning="UPSTREAM_VERSION_OBSERVED",
                     version="1.4.1", downloadAuthorized=True)
        latest = row("hypopg", ident="github:new", pg="18")
        latest.update(source="GITHUB_DISCOVERY_ONLY", provider="HypoPG/hypopg",
                      assetName="hypopg-1.4.5-pg18-x64.zip",
                      versionMeaning="UPSTREAM_VERSION_OBSERVED",
                      version="1.4.5")
        with self.assertRaises(Denied):
            self.compile(plan([older, latest]))

    def test_poisoned_unchosen_bundle_cannot_hide(self):
        older = row("postgis", ident="osgeo:pg17:3.6.2", pg="17")
        older.update(assetName="postgis-bundle-pg17-3.6.2x64.zip",
                     version="3.6.2", mirrorAuthorized=True)
        latest = row("postgis", ident="osgeo:pg18:3.7.0", pg="18")
        with self.assertRaises(Denied):
            self.compile(plan([older, latest]), single_bundle=True)

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
