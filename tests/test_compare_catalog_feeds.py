#!/usr/bin/env python3
"""Canonical feed comparison: only the root and latest-admission source
SHAs may differ between two builds of the same payload."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import compare_catalog_feeds as compare


SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_OLD = "c" * 40


def feed(commit, *, package_sha="d" * 64, historical_commit=SHA_OLD):
    return {
        "schemaVersion": "pgextwin-signed-catalog-zip-feed/v3",
        "repository": "pgextwin/catalog",
        "catalogCommit": commit,
        "postgresqlMajors": ["15", "16", "17", "18", "19"],
        "extensions": [{
            "extension": "orafce",
            "repositoryId": 123,
            "latestReleaseTag": "v2-windows.1",
            "releases": [
                {"releaseTag": "v1-windows.1", "releaseId": 11,
                 "admission": {"catalogCommit": historical_commit},
                 "packages": [{"pgMajor": "15", "sha256": "e" * 64}]},
                {"releaseTag": "v2-windows.1", "releaseId": 12,
                 "admission": {"catalogCommit": commit},
                 "packages": [{"pgMajor": "15", "sha256": package_sha}]},
            ],
        }],
        "verificationLevel": "CATALOG_FEED_SIGNED_CLAIM_ONLY",
        "extensionSignatureVerified": False,
        "publicationAuthorized": False,
        "installAuthorized": False,
    }


class CanonicalFeedComparison(unittest.TestCase):
    def test_source_sha_only_difference_matches(self):
        left = compare.normalized_bytes(feed(SHA_A), SHA_A)
        right = compare.normalized_bytes(feed(SHA_B), SHA_B)
        self.assertEqual(left, right)

    def test_package_change_differs(self):
        left = compare.normalized_bytes(feed(SHA_A), SHA_A)
        right = compare.normalized_bytes(feed(SHA_B, package_sha="f" * 64), SHA_B)
        self.assertNotEqual(left, right)

    def test_historical_admission_change_differs(self):
        left = compare.normalized_bytes(feed(SHA_A), SHA_A)
        right = compare.normalized_bytes(feed(SHA_B, historical_commit=SHA_A), SHA_B)
        self.assertNotEqual(left, right)

    def test_root_must_name_own_checkout(self):
        with self.assertRaises(ValueError):
            compare.normalized_bytes(feed(SHA_A), SHA_B)

    def test_latest_admission_must_name_own_checkout(self):
        broken = feed(SHA_A)
        broken["extensions"][0]["releases"][1]["admission"]["catalogCommit"] = SHA_OLD
        with self.assertRaises(ValueError):
            compare.normalized_bytes(broken, SHA_A)

    def test_input_feed_is_not_mutated(self):
        original = feed(SHA_A)
        snapshot = copy.deepcopy(original)
        compare.normalized(original, SHA_A)
        self.assertEqual(original, snapshot)


if __name__ == "__main__":
    unittest.main()
