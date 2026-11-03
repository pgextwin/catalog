"""Issue #112 external source registry: read-only metadata, never authorization."""
import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema/external-windows-source-v1.schema.json").read_text())
REGISTRY = json.loads((ROOT / "external/windows-candidates-v1.json").read_text())
INVENTORY = json.loads((ROOT / "evidence/issue112-external-release-inventory-20261103.json").read_text())


class ExternalSourceRegistryTests(unittest.TestCase):
    def test_schema_valid_and_all_metadata_only(self):
        Draft202012Validator.check_schema(SCHEMA)
        errors = list(Draft202012Validator(SCHEMA, format_checker=FormatChecker()).iter_errors(REGISTRY))
        self.assertEqual([], errors)
        self.assertFalse(REGISTRY["publicationAuthorized"])
        self.assertFalse(REGISTRY["redistributionAuthorized"])
        for c in REGISTRY["candidates"]:
            self.assertFalse(c["downloadAuthorized"])
            self.assertFalse(c["compatibilityVerified"])
            self.assertFalse(c["provenanceVerified"])
            self.assertIsNone(c["originalSha256"])
            self.assertEqual("metadata-only", c["verificationState"])

    def test_complete_windows_assets_and_lossless_ids(self):
        observed = {
            (repo["repo"], r["releaseId"], a["assetId"], a["name"], a["digest"])
            for repo in INVENTORY["repositories"]
            for r in repo["releases"]
            for a in r["windowsAssets"]
        }
        indexed = {
            (c["sourceRepo"], c["releaseId"], c["assetId"], c["assetName"], c["apiDigest"])
            for c in REGISTRY["candidates"]
        }
        self.assertEqual(observed, indexed)
        self.assertEqual(len(observed), len(REGISTRY["candidates"]))
        self.assertEqual(197, len(observed))
        self.assertEqual(3, len(INVENTORY["repositories"]))
        for repo in INVENTORY["repositories"]:
            self.assertEqual(2, repo["pagesScanned"])
            self.assertEqual(repo["releasesSeen"], len(repo["releases"]))

    def test_missing_digest_is_retained_not_promoted(self):
        missing = [c for c in REGISTRY["candidates"] if c["apiDigest"] is None]
        self.assertEqual(147, len(missing))
        self.assertTrue(all(c["originalSha256"] is None for c in missing))

    def test_archive_eol_and_release_asset_versions_independent(self):
        self.assertTrue(any(c["lifecycle"] == "eol" for c in REGISTRY["candidates"]))
        self.assertTrue(any(c["releaseTag"] == "ORACLE_FDW_2_8_0" and
                            c["assetVersion"] == "2.8.1"
                            for c in REGISTRY["candidates"]))

    def test_metadata_claim_cannot_become_download_authority(self):
        c = copy.deepcopy(REGISTRY)
        c["candidates"][0]["downloadAuthorized"] = True
        self.assertTrue(list(Draft202012Validator(SCHEMA).iter_errors(c)))
        c = copy.deepcopy(REGISTRY)
        c["candidates"][0]["originalSha256"] = "a" * 64
        self.assertTrue(list(Draft202012Validator(SCHEMA).iter_errors(c)))

    def test_non_https_and_duplicate_unsafe_name(self):
        c = copy.deepcopy(REGISTRY)
        c["candidates"][0]["assetUrl"] = "file:///tmp/evil"
        self.assertTrue(list(Draft202012Validator(SCHEMA).iter_errors(c)))
        c = copy.deepcopy(REGISTRY)
        c["candidates"][0]["assetName"] = "../evil.zip"
        self.assertTrue(list(Draft202012Validator(SCHEMA).iter_errors(c)))


if __name__ == "__main__":
    unittest.main()
