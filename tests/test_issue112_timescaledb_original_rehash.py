"""Offline hostile tests for TimescaleDB official original rehash (DENY-only)."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_timescaledb_original_rehash as probe


def make_zip(members=None):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in (members or [
            ("lib/timescaledb.dll", b"test PE payload"),
            ("LICENSE", b"fixture license text"),
        ]):
            archive.writestr(name, data)
    return stream.getvalue()


class Response(io.BytesIO):
    def geturl(self):
        return "https://release-assets.githubusercontent.com/test-audit-fixture"


class Opener:
    def __init__(self, data):
        self.data = data

    def open(self, request, timeout=None):
        return Response(self.data)


class TimescaleOriginalAudit(unittest.TestCase):
    def test_exact_three_official_pins_are_observed_not_authorized(self):
        self.assertEqual(probe.MAJORS, ("16", "17", "18"))
        for pg in probe.MAJORS:
            source = probe.original_pin(pg)
            self.assertEqual(source["releaseId"], 418582851)
            self.assertRegex(source["sha256"], r"^[a-f0-9]{64}$")
            self.assertGreater(source["size"], 9_000_000)
            self.assertEqual(
                source["url"], "https://github.com/timescale/timescaledb/releases/"
                f"download/2.31.0/timescaledb-postgresql-{pg}-windows-amd64.zip")
        for unsupported in ("14", "15", "19", "../17", "", "all"):
            with self.subTest(pg=unsupported), self.assertRaises(ValueError):
                probe.original_pin(unsupported)

    def test_redirect_must_stay_on_approved_https_hosts(self):
        for url in (
            "http://github.com/timescale/timescaledb/release.zip",
            "https://example.invalid/release.zip",
            "https://github.com.evil.invalid/release.zip",
            "https://github.com:444/release.zip",
            "https://user:pass@github.com/release.zip",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                probe.checked_url(url)
        self.assertEqual(
            probe.checked_url("https://release-assets.githubusercontent.com/download"),
            "https://release-assets.githubusercontent.com/download")

    def test_safe_zip_contents_crc_and_notice_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "good.zip"
            path.write_bytes(make_zip())
            report = probe.inspect_zip(path)
            self.assertEqual(report["dllMembers"], 1)
            self.assertEqual(report["potentialNoticePaths"], ["LICENSE"])

    def test_zip_traversal_case_duplicate_missing_dll_rejected(self):
        candidates = (
            [("../escape.dll", b"x")],
            [("c:\\escape.dll", b"x")],
            [("lib/TIMESCALEDB.dll", b"x"), ("lib/timescaledb.dll", b"y")],
            [("README", b"not a Windows library")],
        )
        with tempfile.TemporaryDirectory() as tmp:
            for index, members in enumerate(candidates):
                with self.subTest(index=index):
                    path = Path(tmp) / f"bad{index}.zip"
                    path.write_bytes(make_zip(members))
                    with self.assertRaises(ValueError):
                        probe.inspect_zip(path)

    def test_fake_original_fails_sha256_and_size_before_zip_audit(self):
        data = make_zip()
        pin = {"pg": "16", "name": "fake.zip", "assetId": 12,
               "releaseId": 418582851, "size": len(data),
               "sha256": hashlib.sha256(data).hexdigest(),
               "url": probe.RELEASE_URL + "/fake.zip"}
        with mock.patch.object(probe, "original_pin", return_value=pin):
            with self.assertRaisesRegex(ValueError, "mismatch"):
                probe.audit("16", opener=Opener(data[:-1]))
            wrong_data = data[:-1] + b"x"
            with self.assertRaisesRegex(ValueError, "mismatch"):
                probe.audit("16", opener=Opener(wrong_data))
            with self.assertRaisesRegex(ValueError, "exceed"):
                probe.audit("16", opener=Opener(data + b"more"))

    def test_successful_fixture_still_fails_closed_for_public(self):
        data = make_zip()
        pin = {"pg": "17", "name": "fixture.zip", "assetId": 34,
               "releaseId": 418582851, "size": len(data),
               "sha256": hashlib.sha256(data).hexdigest(),
               "url": probe.RELEASE_URL + "/fixture.zip"}
        with mock.patch.object(probe, "original_pin", return_value=pin):
            receipt = probe.audit("17", opener=Opener(data))
        self.assertEqual(receipt["independentSha256"], pin["sha256"])
        self.assertTrue(receipt["zipSafetyChecked"])
        for flag in ("producerSourceToBinaryAttestationVerified",
                     "rightsAndNoticesClosureVerified", "windowsRuntimeVerified",
                     "independentSignedAdmission", "publicGetAuthorized",
                     "mirrorAuthorized", "redistributionAuthorized",
                     "releaseAuthorized", "publisherAuthorized"):
            self.assertIs(receipt[flag], False, flag)


if __name__ == "__main__":
    unittest.main()
