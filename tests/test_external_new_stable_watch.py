"""Offline contract tests for metadata-only daily stable provider watch."""
import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import external_new_stable_watch as watch


def release(tag, rid=1, aids=(101,), prerelease=False):
    return {"tag": tag, "releaseId": rid, "publishedAt": "2026-11-11T00:00:00Z",
            "draft": False, "prerelease": prerelease,
            "windowsAssets": [{"assetId": asset, "name": f"test-{asset}.zip"}
                              for asset in aids]}


def inventory(*releases):
    return {"schemaVersion": "pgextwin-external-windows-release-inventory/v1",
            "trust": "UNVERIFIED_METADATA_ONLY",
            "publicationAuthorized": False, "redistributionAuthorized": False,
            "repositories": [{"repo": "example/provider", "releases": list(releases)}]}


CONFIG = {"trust": "READ_ONLY_METADATA_NEVER_AUTHORIZE",
          "providers": [{"repo": "example/provider", "extension": "pgvector"}]}


class DailyWatchTests(unittest.TestCase):
    def test_release_tag_comparison_is_not_extension_version(self):
        self.assertEqual((2, 9, 0, 0), watch.tag_key("ORACLE_FDW_2_9_0"))
        self.assertEqual((0, 108, 3, 0), watch.tag_key("v0.108.3"))
        self.assertEqual((20260107, 0, 0, 0), watch.tag_key("v20260107"))
        for bad in ("v1.2.3-rc1", "1.0-beta", "../evil", "v1.2.3+local"):
            self.assertIsNone(watch.tag_key(bad))

    def test_tracked_stable_release_does_not_create_false_new_version(self):
        r = watch.analyze(inventory(release("1.4.1")),
                          CONFIG, {"example/provider": {("1.4.1", 101)}})
        self.assertEqual(r["providers"][0]["status"], "TRACKED")
        self.assertEqual(r["newStableCount"], 0)
        self.assertFalse(r["downloadAuthorized"])
        self.assertFalse(r["publicationAuthorized"])

    def test_new_stable_release_vs_old_pin_is_visible(self):
        r = watch.analyze(inventory(release("1.4.0", 1), release("1.4.2", 2, (201,))),
                          CONFIG, {"example/provider": {("1.4.0", 101)}})
        self.assertEqual(r["providers"][0]["status"], "NEW_STABLE_RELEASE")
        self.assertEqual(r["providers"][0]["latestTag"], "1.4.2")
        self.assertEqual(r["providers"][0]["untrackedAssets"], ["test-201.zip"])
        self.assertEqual(r["newStableCount"], 1)

    def test_untracked_initial_provider_does_not_claim_new_release(self):
        report = watch.analyze(inventory(release("v20260107", 4, (501,))),
                               CONFIG, {})
        self.assertEqual(report["newStableCount"], 0)
        self.assertEqual(report["baselineMissingCount"], 1)
        self.assertEqual(report["providers"][0]["status"], "BASELINE_NOT_ESTABLISHED")
        self.assertFalse(report["publicationAuthorized"])
        self.assertFalse(report["downloadAuthorized"])

    def test_same_stable_version_new_asset_is_not_new_version(self):
        r = watch.analyze(inventory(release("1.4.1", 2, (101, 102))),
                          CONFIG, {"example/provider": {("1.4.1", 101)}})
        self.assertEqual(r["providers"][0]["status"], "UNTRACKED_ASSET_IN_KNOWN_VERSION")
        self.assertEqual(r["providers"][0]["untrackedAssets"], ["test-102.zip"])

    def test_prerelease_and_draft_are_never_new_stable(self):
        r = watch.analyze(inventory(release("1.4.1", 1),
                                    release("1.5.0-rc1", 2, (201,), prerelease=True),
                                    release("1.6.0", 3, (301,), prerelease=True)),
                          CONFIG, {"example/provider": {("1.4.1", 101)}})
        self.assertEqual(r["providers"][0]["status"], "TRACKED")

    def test_missing_provider_and_unsafe_trust_fail_closed(self):
        with self.assertRaises(ValueError):
            watch.analyze(inventory(), {**CONFIG, "trust": "UNTRUSTED"}, {})
        changed = copy.deepcopy(inventory(release("1.0")))
        changed["repositories"].append(copy.deepcopy(changed["repositories"][0]))
        with self.assertRaises(ValueError):
            watch.analyze(changed, CONFIG, {})
        changed = copy.deepcopy(inventory(release("1.0")))
        changed["publicationAuthorized"] = True
        with self.assertRaises(ValueError):
            watch.analyze(changed, CONFIG, {})


    def test_pgroonga_five_originals_cross_check_existing_pins_and_live_api(self):
        baseline = json.loads(watch.PGROONGA_WATCH_BASELINE.read_text("utf-8"))
        assets = [{"assetId": r["assetId"], "name": r["assetName"],
                   "size": r["originalBytes"],
                   "digest": "sha256:" + r["originalSha256"],
                   "state": "uploaded"} for r in baseline["records"]]
        observed = {
            "schemaVersion": "pgextwin-external-windows-release-inventory/v1",
            "trust": "UNVERIFIED_METADATA_ONLY",
            "publicationAuthorized": False,
            "redistributionAuthorized": False,
            "repositories": [{
                "repo": "pgroonga/pgroonga",
                "releases": [{
                    "releaseId": baseline["releaseId"],
                    "tag": baseline["releaseTag"],
                    "draft": False, "prerelease": False,
                    "publishedAt": "2026-10-09T00:00:00Z",
                    "windowsAssets": assets,
                }],
            }],
        }
        tracked = watch.reviewed_pgroonga_baseline(baseline, observed)
        self.assertEqual(5, len(tracked))
        self.assertEqual({("4.1.0", r["assetId"]) for r in baseline["records"]}, tracked)
        config = {"trust": "READ_ONLY_METADATA_NEVER_AUTHORIZE",
                  "providers": [{"repo": "pgroonga/pgroonga",
                                 "extension": "pgroonga"}]}
        report = watch.analyze(observed, config, {"pgroonga/pgroonga": tracked})
        self.assertEqual("TRACKED", report["providers"][0]["status"])
        self.assertFalse(report["downloadAuthorized"])

        changed = copy.deepcopy(observed)
        changed["repositories"][0]["releases"][0]["windowsAssets"][0]["digest"] = (
            "sha256:" + "0" * 64)
        with self.assertRaises(ValueError):
            watch.reviewed_pgroonga_baseline(baseline, changed)
        changed = copy.deepcopy(observed)
        changed["repositories"][0]["releases"][0]["windowsAssets"][0]["size"] += 1
        with self.assertRaises(ValueError):
            watch.reviewed_pgroonga_baseline(baseline, changed)
        changed = copy.deepcopy(baseline)
        changed["records"][0]["originalSha256"] = "0" * 64
        with self.assertRaises(ValueError):
            watch.reviewed_pgroonga_baseline(changed, observed)
        changed = copy.deepcopy(baseline)
        changed["downloadAuthorized"] = True
        with self.assertRaises(ValueError):
            watch.reviewed_pgroonga_baseline(changed, observed)
        changed = copy.deepcopy(baseline)
        changed["records"] = changed["records"][:-1]
        with self.assertRaises(ValueError):
            watch.reviewed_pgroonga_baseline(changed, observed)
        altered = copy.deepcopy(observed)
        altered["repositories"][0]["releases"].append(release("4.2.0", 407467159, (999,)))
        result = watch.analyze(altered, config, {"pgroonga/pgroonga": tracked})
        self.assertEqual("NEW_STABLE_RELEASE", result["providers"][0]["status"])
        self.assertEqual(["test-999.zip"], result["providers"][0]["untrackedAssets"])
        self.assertFalse(result["publicationAuthorized"])

    def test_duplicate_pgroonga_json_baseline_key_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"trust":"DENY","trust":"ALLOW"}',
                       object_pairs_hook=watch.unique_json_pairs)

    def test_historical_issuer_is_only_tracking_not_live_authorization(self):
        cohort = {"schemaVersion": "pgextwin-external-latest-original-pins/v1",
                  "records": []}
        ledger = {"schemaVersion": "pgextwin-windows-source-candidates/v1",
                  "publicationAuthorized": False, "redistributionAuthorized": False,
                  "candidates": []}
        receipt = {"schemaVersion": "pgextwin-external-direct-get-admission/v1",
                   "sourceKind": "EXTERNAL_GITHUB_RELEASE_ASSET",
                   "mirrorAuthorized": False, "redistributionAuthorized": False,
                   "expiresAt": "2026-11-08T00:00:00Z", "records": [
                       {"sourceRepo": "example/provider", "releaseTag": "1.4.1",
                        "assetId": 101}]}
        known = watch.tracked_assets(cohort, [ledger], [receipt])
        report = watch.analyze(inventory(release("1.4.1")), CONFIG, known)
        self.assertEqual(report["providers"][0]["status"], "TRACKED")
        self.assertFalse(report["downloadAuthorized"])

    def test_timescaledb_official_baseline_denies_and_detects_changes(self):
        baseline = json.loads(watch.TIMESCALEDB_WATCH_BASELINE.read_text("utf-8"),
                              object_pairs_hook=watch.unique_json_pairs)
        self.assertEqual(["16", "17", "18"],
                         [x["pgMajor"] for x in baseline["records"]])
        assets = [{"assetId": x["assetId"], "name": x["assetName"],
                   "size": x["apiBytes"], "digest": "sha256:" + x["apiSha256"],
                   "state": "uploaded"} for x in baseline["records"]]
        observed = {
            "schemaVersion": "pgextwin-external-windows-release-inventory/v1",
            "trust": "UNVERIFIED_METADATA_ONLY", "publicationAuthorized": False,
            "redistributionAuthorized": False,
            "repositories": [{"repo": "timescale/timescaledb", "releases": [{
                "releaseId": baseline["releaseId"], "tag": baseline["releaseTag"],
                "draft": False, "prerelease": False,
                "publishedAt": "2026-10-20T16:06:02Z", "windowsAssets": assets}]}]}
        tracked = watch.reviewed_timescaledb_baseline(baseline, observed)
        self.assertEqual(3, len(tracked))
        config = {"trust": "READ_ONLY_METADATA_NEVER_AUTHORIZE",
                  "providers": [{"repo": "timescale/timescaledb",
                                 "extension": "timescaledb"}]}
        report = watch.analyze(observed, config, {"timescale/timescaledb": tracked})
        self.assertEqual("TRACKED", report["providers"][0]["status"])
        self.assertEqual(0, report["newStableCount"])
        self.assertFalse(report["downloadAuthorized"])
        self.assertFalse(report["publicationAuthorized"])
        tampered = copy.deepcopy(observed)
        tampered["repositories"][0]["releases"][0]["windowsAssets"][0]["digest"] = (
            "sha256:" + "0" * 64)
        with self.assertRaises(ValueError):
            watch.reviewed_timescaledb_baseline(baseline, tampered)
        tampered = copy.deepcopy(observed)
        tampered["repositories"][0]["releases"][0]["windowsAssets"].pop()
        with self.assertRaises(ValueError):
            watch.reviewed_timescaledb_baseline(baseline, tampered)
        tampered = copy.deepcopy(baseline)
        tampered["downloadAuthorized"] = True
        with self.assertRaises(ValueError):
            watch.reviewed_timescaledb_baseline(tampered, observed)
        tampered = copy.deepcopy(baseline)
        tampered["records"][0]["apiSha256"] = "0" * 64
        with self.assertRaises(ValueError):
            watch.reviewed_timescaledb_baseline(tampered, observed)
        newer = copy.deepcopy(observed)
        newer["repositories"][0]["releases"].append(
            release("2.32.0", 418582852, (999,)))
        alert = watch.analyze(newer, config, {"timescale/timescaledb": tracked})
        self.assertEqual("NEW_STABLE_RELEASE", alert["providers"][0]["status"])
        self.assertFalse(alert["downloadAuthorized"])


if __name__ == "__main__":
    unittest.main()
