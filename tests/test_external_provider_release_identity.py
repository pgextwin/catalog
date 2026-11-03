"""#112: read-only provider identity checks, never formal external Publisher admission."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from external_signed_asset_pin import build_candidate  # noqa: E402
from external_provider_release_identity import (  # noqa: E402
    compare_exact_source, compare_publisher_intake,
)

COMMIT = "1aa07c3a1a33dcfe73bc4ed5fe683d0e4f26050e"


def snapshot(row):
    name, tag = row["sourceRepo"], row["releaseTag"]
    return {
        "repository": {
            "id": row["repositoryId"],
            "full_name": name,
            "html_url": "https://github.com/" + name,
        },
        "release": {
            "id": row["releaseId"],
            "tag_name": tag,
            "draft": False,
            "prerelease": False,
            "html_url": f"https://github.com/{name}/releases/tag/{tag}",
            "assets": [{
                "id": row["assetId"],
                "name": row["assetName"],
                "size": row["originalBytes"],
                "state": "uploaded",
                "digest": "sha256:" + row["originalSha256"],
                "browser_download_url": row["originalProviderUrl"],
            }]
        },
    }


class ProviderIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidate = build_candidate(ROOT, COMMIT)
        cls.rows = cls.candidate["records"]
        cls.snapshots = {r["sourceRepo"]: snapshot(r) for r in cls.rows}

    def test_exact_two_sources_never_authorize_download_or_mirror(self):
        plan = compare_publisher_intake(ROOT, COMMIT, self.snapshots)
        self.assertEqual(2, plan["metadataIdentityMatched"])
        self.assertEqual(203, plan["downloadDeniedCandidates"])
        self.assertEqual("METADATA_MATCH_ONLY_FORMAL_AUTHORIZATION_REQUIRED",
                         plan["status"])
        self.assertGreaterEqual(len(plan["requiredIndependentGates"]), 7)
        for item in (plan, *plan["records"]):
            for key in ("sourcePublisherAuthorized", "downloadAuthorized",
                        "mirrorAuthorized"):
                self.assertIs(item[key], False)
        for key in ("publicationAuthorized", "redistributionAuthorized",
                    "installAuthorized"):
            self.assertIs(plan[key], False)

    def test_exact_identity_substitution_is_refused(self):
        row = self.rows[0]
        cases = (
            ("repository", "id", 123),
            ("repository", "full_name", "attacker/fork"),
            ("repository", "html_url", "https://example.invalid"),
            ("release", "id", 1),
            ("release", "tag_name", "other"),
            ("release", "draft", True),
            ("release", "prerelease", True),
            ("release", "html_url", "https://example.invalid/release"),
        )
        for section, field, value in cases:
            with self.subTest(section=section, field=field):
                item = snapshot(row)
                item[section][field] = value
                with self.assertRaises(ValueError):
                    compare_exact_source(row, item["repository"], item["release"])

    def test_changed_original_asset_or_stale_metadata_is_refused(self):
        row = self.rows[1]
        for field, value in (
            ("id", 1), ("name", "different.zip"), ("size", 1),
            ("size", True), ("state", "starter"),
            ("digest", "sha256:" + "0" * 64), ("digest", None),
            ("browser_download_url", "https://github.com.evil.invalid/a.zip"),
        ):
            with self.subTest(field=field, value=value):
                item = snapshot(row)
                item["release"]["assets"][0][field] = value
                with self.assertRaises(ValueError):
                    compare_exact_source(row, item["repository"], item["release"])
        for change in ("remove", "duplicate_id", "duplicate_name"):
            with self.subTest(change=change):
                item = snapshot(row)
                if change == "remove":
                    item["release"]["assets"] = []
                else:
                    other = copy.deepcopy(item["release"]["assets"][0])
                    if change == "duplicate_id":
                        other["name"] = "other.zip"
                    else:
                        other["id"] += 1
                    item["release"]["assets"].append(other)
                with self.assertRaises(ValueError):
                    compare_exact_source(row, item["repository"], item["release"])

    def test_neither_signed_candidate_nor_review_can_grant_permission(self):
        for key in ("sourcePublisherAuthorized", "downloadAuthorized", "mirrorAuthorized"):
            with self.subTest(key=key):
                row = copy.deepcopy(self.rows[0])
                row[key] = True
                item = snapshot(row)
                with self.assertRaises(ValueError):
                    compare_exact_source(row, item["repository"], item["release"])

    def test_source_set_is_exact_and_cannot_expand(self):
        for cases in (
            {},
            {self.rows[0]["sourceRepo"]: self.snapshots[self.rows[0]["sourceRepo"]]},
            {**self.snapshots, "attacker/fork": self.snapshots[self.rows[0]["sourceRepo"]]},
        ):
            with self.assertRaises(ValueError):
                compare_publisher_intake(ROOT, COMMIT, cases)
        with self.assertRaises(ValueError):
            compare_publisher_intake(ROOT, "main", self.snapshots)
        with self.assertRaises(ValueError):
            compare_publisher_intake(ROOT, COMMIT, {
                key: {**value, "claimedAuthorization": True}
                for key, value in self.snapshots.items()
            })


if __name__ == "__main__":
    unittest.main()
