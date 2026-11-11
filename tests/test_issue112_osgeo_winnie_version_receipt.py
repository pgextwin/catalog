"""Offline hostile tests for nonpublishing Winnie version receipt. No HTTP."""
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_osgeo_winnie_version_receipt as audit


class WinnieVersionReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "untrusted.zip"
        self.pg = "18"
        self.version = audit.ORIGINALS[self.pg][0]
        self.name = "postgis-bundle-pg18-3.7.0x64/version.txt"

    def archive(self, rows):
        with zipfile.ZipFile(self.path, "w") as dst:
            for name, body in rows:
                dst.writestr(name, body)
        return zipfile.ZipFile(self.path, "r")

    def test_self_report_is_not_a_rights_or_provenance_claim(self):
        value = b"GEOS VERSION: 3.14.1 https://example.invalid\n" \
                b"GDAL VERSION: 3.12.0\nPROJ VERSION: 9.7.0\n"
        with self.archive([(self.name, value)]) as src:
            obs = audit.receipt(src, self.pg, self.version)
        self.assertEqual(obs["versionTxtBytes"], len(value))
        self.assertEqual(obs["versionTxtSha256"], hashlib.sha256(value).hexdigest())
        self.assertEqual(obs["packagingComponentVersionClaims"],
                         {"GDAL": "3.12.0", "GEOS": "3.14.1", "PROJ": "9.7.0"})
        report = audit.denied_report(self.pg, self.version,
                                    audit.ORIGINALS[self.pg][1],
                                    audit.ORIGINALS[self.pg][2], obs)
        self.assertEqual(report["status"], "CANDIDATE_ONLY")
        for gate in ("producerSourceRevisionVerified",
                     "sourceToExactDllBytesAttested",
                     "componentLicenseNoticeClosureVerified",
                     "runtimeDependencyClosureVerified",
                     "independentSignedAdmission", "publicGetAuthorized",
                     "mirrorAuthorized", "publisherAuthorized",
                     "releaseAuthorized"):
            self.assertIs(report[gate], False, gate)

    def test_absent_version_file_does_not_claim_observed_version(self):
        with self.archive([("unexpected/version.txt", b"GEOS VERSION: 1.0.0")]) as src:
            obs = audit.receipt(src, self.pg, self.version)
        self.assertFalse(obs["versionTxtFound"])
        self.assertEqual(obs["packagingComponentVersionClaims"], {})
        self.assertEqual(obs["manifestObservation"], "EXPECTED_VERSION_TXT_ABSENT")

    def test_other_pg_version_is_not_accepted(self):
        with self.archive([(self.name, b"GEOS VERSION: 3.14.1")]) as src:
            for pg, version in (("17", self.version), ("18", "3.6.2"),
                                ("19", self.version)):
                with self.assertRaisesRegex(ValueError, "pinned"):
                    audit.receipt(src, pg, version)

    def test_duplicate_casefold_member_is_rejected(self):
        with self.archive([(self.name, b"GEOS VERSION: 3.14.1"),
                           (self.name.upper(), b"GEOS VERSION: 3.14.2")]) as src:
            with self.assertRaisesRegex(ValueError, "duplicate"):
                audit.receipt(src, self.pg, self.version)

    def test_duplicate_component_label_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            audit.parse_manifest(b"GEOS VERSION: 3.14.1\nGEOS VERSION: 3.14.2\n")

    def test_non_utf8_nul_or_oversized_text_rejected(self):
        for value in (b"\xff", b"GEOS VERSION: 1.0.0\x00",
                      b"x" * (audit.MAX_MANIFEST_BYTES + 1),
                      b"GEOS VERSION: 1\n" * 513):
            with self.subTest(length=len(value)):
                with self.assertRaises(ValueError):
                    audit.parse_manifest(value)

    def test_bad_version_token_cannot_be_claimed(self):
        for value in (b"GDAL VERSION: ../evil",
                      b"PROJ VERSION: https://evil.invalid",
                      b"GEOS VERSION: 3.14.1\r\nGEOS VERSION: 3.15.0"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    audit.parse_manifest(value)

    def test_lookalike_names_are_not_a_manifest(self):
        for name in ("../" + self.name,
                     self.name + ".bak",
                     "postgis-bundle-pg17-3.7.0x64/version.txt",
                     "postgis-bundle-pg18-3.7.0x64/notes/version.txt"):
            with self.subTest(name=name):
                with self.archive([(name, b"GEOS VERSION: 9.9.9")]) as src:
                    self.assertFalse(audit.receipt(src, self.pg, self.version)["versionTxtFound"])

    def test_local_fake_archive_must_fail_exact_original_pin(self):
        with self.archive([(self.name, b"GEOS VERSION: 3.14.1")]):
            pass
        with self.assertRaisesRegex(ValueError, "size"):
            audit.audit(self.path, "18")
        with self.assertRaisesRegex(ValueError, "major"):
            audit.audit(self.path, "19")

    def test_pins_cover_supported_majors_and_are_not_content_discovery(self):
        self.assertEqual(set(audit.ORIGINALS), {"14", "15", "16", "17", "18"})
        for version, size, sha in audit.ORIGINALS.values():
            self.assertRegex(version, r"^3\.[0-9]+\.[0-9]+$")
            self.assertGreater(size, 1000000)
            self.assertRegex(sha, r"^[a-f0-9]{64}$")


if __name__ == "__main__":
    unittest.main()
