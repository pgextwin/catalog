"""Read-only exact-byte HypoPG 3-PG cohort declarations; no signed admission."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from external_direct_get_intake import validate_intake, inspect_intake
from external_direct_link_review import strict_read

PATH = ROOT / "config/issue112-hypopg-original-get-intake-v1.json"
EXPECTED = {
    "14": (164673161, 23115,
           "ac1114d1392494e688b5b6b6f151aebe6ccab2d8ae1a004ec510669c47ef3634"),
    "15": (164673166, 23123,
           "d23ea9ba7d064ee08e431b12ade50bed4b19a725b5f4df1e088e79e4af8d08ec"),
    "16": (164673171, 22997,
           "7afd7cda50050829787d4e901fc8292cf1eb2bc5ad59c996a92e414a1bead1f7"),
}


class Cohort(unittest.TestCase):
    def setUp(self):
        self.doc = strict_read(PATH)

    def test_three_review_only_exact_source_records(self):
        rows = validate_intake(self.doc)
        self.assertEqual(len(rows), 3)
        self.assertEqual({r["pgMajor"] for r in rows}, set(EXPECTED))
        for r in rows:
            identity = (r["assetId"], r["originalBytes"], r["originalSha256"])
            self.assertEqual(identity, EXPECTED[r["pgMajor"]])
            self.assertEqual((r["repositoryId"], r["releaseId"], r["releaseTag"]),
                             (37308208, 153113229, "1.4.1"))
            self.assertEqual(r["sourceRepo"], "HypoPG/hypopg")
            self.assertEqual((r["runtimeEvidence"]["runId"],
                              r["runtimeEvidence"]["headSha"]),
                             (42457245493, "52e695e4959a07e18971e26d293ff4249c071237"))
            self.assertFalse(r["downloadAuthorized"])
            self.assertFalse(r["mirrorAuthorized"])
            self.assertFalse(r["sourcePublisherAuthorized"])
        report = inspect_intake(document=self.doc)
        self.assertFalse(report["downloadAuthorized"])
        self.assertFalse(report["independentSigstoreAuthorizedPin"])

    def test_unknown_provider_or_historical_p3_source_cannot_promote(self):
        d = copy.deepcopy(self.doc)
        d["records"][0]["sourceRepo"] = "pgextwin/catalog"
        with self.assertRaises(ValueError): validate_intake(d)
        d = copy.deepcopy(self.doc)
        d["records"][0]["assetId"] = d["records"][1]["assetId"]
        with self.assertRaises(ValueError): validate_intake(d)

    def test_trust_flip_and_duplicate_are_denied(self):
        for key in ("downloadAuthorized","publicationAuthorized",
                    "independentSignedAdmission","mirrorAuthorized"):
            d = copy.deepcopy(self.doc)
            d[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_intake(d)
        d = copy.deepcopy(self.doc)
        d["records"].append(copy.deepcopy(d["records"][0]))
        with self.assertRaises(ValueError): validate_intake(d)

    def test_forged_bytes_url_and_pg_scope_are_denied(self):
        for key, value in (
            ("originalSha256", "1"),
            ("originalProviderUrl", "https://example.invalid/zip"),
            ("pgMajor", "19"),
            ("targetEnvironment", "Linux"),
            ("runtimeEvidence", {}),
        ):
            d = copy.deepcopy(self.doc)
            d["records"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_intake(d)

    def test_exact_json_is_deny_only_and_no_zip(self):
        self.assertTrue(PATH.is_file())
        self.assertFalse(any(p.suffix in (".zip", ".exe", ".7z") for p in PATH.parent.iterdir()))
        self.assertFalse(self.doc["downloadAuthorized"])
        self.assertFalse(self.doc["publicationAuthorized"])
        self.assertEqual(self.doc["authorizationIssuer"], "NONE")


if __name__ == "__main__":
    unittest.main()
