"""#112: signed external Catalog pin *candidate* never grants download authority."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from external_signed_asset_pin import build_candidate, canonical_bytes  # noqa: E402
from external_direct_link_review import REVIEW, strict_read  # noqa: E402

COMMIT = "2d8422be90af3b7e54539ed8649069a2dfb10d48"


class ExternalSignedAssetPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.review = strict_read(ROOT / REVIEW)

    def test_exact_source_specific_pins_are_deny_only(self):
        data = build_candidate(ROOT, COMMIT)
        self.assertEqual("pgextwin-external-catalog-asset-pin-candidate/v1",
                         data["schemaVersion"])
        self.assertEqual(COMMIT, data["catalogCommit"])
        self.assertEqual(hashlib.sha256((ROOT / REVIEW).read_bytes()).hexdigest(),
                         data["reviewEvidenceSha256"])
        self.assertEqual(2, data["originalProviderAssets"])
        self.assertEqual(203, data["discoveryCandidates"])
        self.assertEqual(203, data["downloadDeniedCandidates"])
        self.assertEqual(
            [("andreiramani/pgvector_pgsql_windows", 419235203, 661612613),
             ("laurenz/oracle_fdw", 335861225, 442625860)],
            [(r["sourceRepo"], r["releaseId"], r["assetId"])
             for r in data["records"]])
        self.assertTrue(all(r["sourceGroup"] == "external" and
                            r["pgMajor"] == "18" and
                            len(r["originalSha256"]) == 64 and
                            r["originalProviderUrl"].startswith("https://github.com/") and
                            r["originalBinarySignatureVerified"] is False and
                            r["downloadAuthorized"] is False and
                            r["mirrorAuthorized"] is False and
                            r["sourcePublisherAuthorized"] is False
                            for r in data["records"]))
        for name in ("originalBinarySignatureVerified", "publicationAuthorized",
                     "sourcePublisherAuthorized", "downloadAuthorized",
                     "mirrorAuthorized", "redistributionAuthorized",
                     "installAuthorized"):
            self.assertIs(data[name], False, name)

    def test_deterministic_canonical_bytes(self):
        first = canonical_bytes(build_candidate(ROOT, COMMIT))
        second = canonical_bytes(build_candidate(ROOT, COMMIT))
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        self.assertEqual(first, canonical_bytes(json.loads(first)))
        self.assertLess(len(first), 100000)

    def test_untrusted_source_cannot_inject_authority(self):
        for field in ("publicationAuthorized", "downloadAuthorized",
                      "signedExternalCatalogPin", "redistributionAuthorized",
                      "mirrorAuthorized"):
            with self.subTest(field=field):
                review = copy.deepcopy(self.review)
                review[field] = True
                with self.assertRaises(ValueError):
                    build_candidate(ROOT, COMMIT, review)
        for field in ("downloadAuthorized", "mirrorAuthorized"):
            with self.subTest(field=field):
                review = copy.deepcopy(self.review)
                review["records"][0][field] = True
                with self.assertRaises(ValueError):
                    build_candidate(ROOT, COMMIT, review)

    def test_original_bytes_ids_rights_and_runtime_are_bound(self):
        for field, value in (
            ("originalSha256", "0" * 64), ("releaseId", 123),
            ("assetId", 123), ("repositoryId", 123),
            ("originalBytes", 0), ("originalProviderUrl", "https://evil.test/x"),
            ("targetEnvironment", "wrong ABI"), ("packageLicenseUrl", ""),
            ("noticeTreatment", ""), ("runtimeEvidence", "https://evil.test/run")
        ):
            with self.subTest(field=field):
                review = copy.deepcopy(self.review)
                review["records"][0][field] = value
                with self.assertRaises(ValueError):
                    build_candidate(ROOT, COMMIT, review)

    def test_no_forged_commit_or_expanded_scope(self):
        for commit in ("main", "0" * 39, "a" * 41, "A" * 40, ""):
            with self.subTest(commit=commit):
                with self.assertRaises(ValueError):
                    build_candidate(ROOT, commit)
        review = copy.deepcopy(self.review)
        review["records"].append(copy.deepcopy(review["records"][0]))
        with self.assertRaises(ValueError):
            build_candidate(ROOT, COMMIT, review)
        review = copy.deepcopy(self.review)
        review["evidenceCatalogCommit"] = "0" * 40
        with self.assertRaises(ValueError):
            build_candidate(ROOT, COMMIT, review)


if __name__ == "__main__":
    unittest.main()
