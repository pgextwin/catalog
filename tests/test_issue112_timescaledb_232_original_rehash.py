"""Hostile offline tests for new 2.32.0 original byte audit; no upstream GET."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_timescaledb_232_original_rehash as probe


class Response(io.BytesIO):
    def geturl(self):
        return "https://release-assets.githubusercontent.com/test-232-fixture"


class Opener:
    def __init__(self, body):
        self.body = body

    def open(self, request, timeout=None):
        return Response(self.body)


def fixture_zip():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        z.writestr("timescaledb/setup.exe", b"private-fixture")
        z.writestr("timescaledb/lib/timescaledb.dll", b"fake-Windows-DLL")
        z.writestr("timescaledb/LICENSE", b"fixture-not-rights-clearance")
    return stream.getvalue()


class IndependentLatestAudit(unittest.TestCase):
    def test_latest_three_pins_distinct_from_historical_bytes(self):
        expected = {
            "16": (739177731, 9637877,
                   "69124f50da0206e6fa92bae9918f200875a406977cb18fd9e92187d4910f179a"),
            "17": (739179170, 9638195,
                   "773596b56f53ac97595b8c36e09ae7f1125bdbc28f6aaa3efa0c8d92bf129c17"),
            "18": (739179122, 9639648,
                   "309eba6bb24c3562b9ecfd279ff1bbe0eb638eaed8b16395c839047c670a9c45"),
        }
        for pg, (asset_id, size, sha) in expected.items():
            pin = probe.original_pin(pg)
            self.assertEqual((pin["assetId"], pin["size"], pin["sha256"]),
                             (asset_id, size, sha))
            self.assertEqual(pin["url"], probe.RELEASE_URL + "/" + pin["name"])
        for pg in ("14", "15", "19", "all", "", "../17"):
            with self.subTest(pg=pg), self.assertRaises(ValueError):
                probe.original_pin(pg)

    def test_fake_same_size_different_bytes_and_truncated_zip_deny(self):
        data = fixture_zip()
        pin = {"pg": "16", "name": "test.zip",
               "assetId": 739177731, "releaseId": probe.RELEASE_ID,
               "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
               "url": probe.RELEASE_URL + "/test.zip"}
        with mock.patch.object(probe, "original_pin", return_value=pin):
            with self.assertRaises(ValueError):
                probe.audit("16", opener=Opener(data[:-1]))
            with self.assertRaises(ValueError):
                probe.audit("16", opener=Opener(data[:-1] + b"x"))
            with self.assertRaises(ValueError):
                probe.audit("16", opener=Opener(data + b"tamper"))

    def test_successful_fixture_cannot_authorize_public_get_or_producer(self):
        data = fixture_zip()
        pin = {"pg": "18", "name": "test.zip",
               "assetId": 739179122, "releaseId": probe.RELEASE_ID,
               "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
               "url": probe.RELEASE_URL + "/test.zip"}
        with mock.patch.object(probe, "original_pin", return_value=pin):
            receipt = probe.audit("18", opener=Opener(data))
        self.assertTrue(receipt["zipSafetyChecked"])
        self.assertEqual(receipt["independentSha256"], pin["sha256"])
        for flag in ("producerSourceToBinaryAttestationVerified",
                     "rightsAndNoticesClosureVerified", "windowsRuntimeVerified",
                     "independentSignedAdmission", "publicGetAuthorized",
                     "mirrorAuthorized", "redistributionAuthorized",
                     "releaseAuthorized", "publisherAuthorized"):
            self.assertIs(receipt[flag], False)

    def test_fake_promoted_review_or_changed_source_deny(self):
        good = {
            "source": "TIMESCALEDB_API_ONLY_NEW_STABLE_CANDIDATE",
            "version": "2.32.0", "pgMajor": "16",
            "provider": "timescale/timescaledb",
            "assetName": "timescaledb-postgresql-16-windows-amd64.zip",
            "format": "zip", "packageIdentity":
                "github-metadata:timescale/timescaledb:442824242:739177731",
            "originalBytes": None, "originalSha256": None,
            "apiObservedBytes": 9637877, "apiObservedSha256": "a"*64,
            "blockers": ["INDEPENDENT_ORIGINAL_BYTES_NOT_REHASHED"],
            **dict.fromkeys(probe.DENY, False),
        }
        for change in (
            {"source": "TIMESCALEDB_REHASHED_ORIGINAL_ONLY"},
            {"originalSha256": "a"*64},
            {"downloadAuthorized": True},
            {"publisherAuthorized": True},
            {"packageIdentity": "github-metadata:other/repo:442824242:739177731"},
        ):
            row = {**good, **change}
            with mock.patch.object(probe, "make_plan", return_value={
                "selected": [row], "admittedAssets": 0, **dict.fromkeys(probe.DENY, False),
            }):
                with self.assertRaises(ValueError):
                    probe.original_pin("16")


if __name__ == "__main__":
    unittest.main()
