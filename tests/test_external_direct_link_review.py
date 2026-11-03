"""Original-provider PG18 link/notice review is never a downloader permit."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from external_direct_link_review import REVIEW, strict_read, validate_review  # noqa: E402


class DirectLinkReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.review = strict_read(ROOT / REVIEW)

    def reject(self, mutator):
        doc = copy.deepcopy(self.review)
        mutator(doc)
        with self.assertRaises(ValueError):
            validate_review(ROOT, doc)

    def test_two_existing_evidence_linked_and_still_denied(self):
        state = validate_review()
        self.assertEqual(2, state["referenceLinksReviewed"])
        self.assertEqual(0, state["signedExternalCatalogPins"])
        self.assertIs(state["downloadAuthorized"], False)
        self.assertIs(state["mirrorAuthorized"], False)
        self.assertEqual("CANDIDATE_ONLY", state["scope"])

    def test_unsigned_review_cannot_become_publication_authority(self):
        for field in (
            "publicationAuthorized", "downloadAuthorized", "mirrorAuthorized",
            "redistributionAuthorized", "signedExternalCatalogPin"
        ):
            with self.subTest(field=field):
                self.reject(lambda d: d.__setitem__(field, True))
        for field in ("downloadAuthorized", "mirrorAuthorized", "mirrorRightsReviewed"):
            with self.subTest(field=field):
                self.reject(lambda d: d["records"][0].__setitem__(field, True))

    def test_no_unknown_or_moved_assets_and_digests(self):
        for field, replacement in (
            ("assetId", 1), ("releaseId", 1),
            ("originalSha256", "0" * 64),
            ("originalBytes", 1), ("repositoryId", 1),
            ("releaseTag", "other"), ("assetName", "evil.zip"),
            ("targetEnvironment", "PG18 arbitrary ABI"),
        ):
            with self.subTest(field=field):
                self.reject(lambda d, f=field, r=replacement: d["records"][0].__setitem__(f, r))
        self.reject(lambda d: d["records"].append(copy.deepcopy(d["records"][0])))
        self.reject(lambda d: d["records"][1].__setitem__("sourceRepo", "laurenz/oracle_fdw"))

    def test_notice_identity_and_url_must_be_exact(self):
        for url in (
            "http://github.com/laurenz/oracle_fdw/releases/download/ORACLE_FDW_2_9_0/oracle_fdw-2.9.0-pg18-win64.zip",
            "https://github.com.evil.test/laurenz/oracle_fdw/releases/download/ORACLE_FDW_2_9_0/oracle_fdw-2.9.0-pg18-win64.zip",
            "https://github.com/laurenz/oracle_fdw/releases/download/ORACLE_FDW_2_9_0/oracle_fdw-2.9.0-pg18-win64.zip?mirror=1",
        ):
            with self.subTest(url=url):
                self.reject(lambda d, value=url: d["records"][0].__setitem__("originalProviderUrl", value))
        self.reject(lambda d: d["records"][0].__setitem__("noticeTreatment", ""))
        self.reject(lambda d: d["records"][1].__setitem__("providerStatusNotice", "Official release"))
        self.reject(lambda d: d["records"][1].__setitem__("packageLicenseUrl", "https://example.com/LICENSE"))
        self.reject(lambda d: d["records"][0].__setitem__("dependencyLicenseUrl", None))

    def test_extra_review_does_not_override_unsigned_metadata(self):
        self.reject(lambda d: d["records"].pop())
        self.reject(lambda d: d.__setitem__("scope", "DOWNLOAD_APPROVED"))


if __name__ == "__main__":
    unittest.main()
