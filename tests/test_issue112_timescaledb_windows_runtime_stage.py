"""Offline adversarial staging checks: no external GET, no public admission."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_timescaledb_windows_runtime_stage as stage


def fixture(entries=None):
    stream = io.BytesIO()
    if entries is None:
        entries = [
            ("timescaledb/setup.exe", b"stub Windows setup"),
            ("timescaledb/lib/timescaledb.dll", b"stub DLL"),
            ("timescaledb/LICENSE", b"sample notice"),
        ]
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return stream.getvalue()


class FakeResponse(io.BytesIO):
    def geturl(self):
        return "https://release-assets.githubusercontent.com/fixture"


class FakeOpener:
    def __init__(self, value):
        self.value = value

    def open(self, request, timeout=None):
        return FakeResponse(self.value)


class RuntimeStagingTests(unittest.TestCase):
    def test_exact_bytes_and_create_only_staging_still_deny_public_get(self):
        data = fixture()
        pin = {"pg": "16", "name": "fixture.zip", "size": len(data),
               "sha256": hashlib.sha256(data).hexdigest(),
               "releaseId": 418582851, "assetId": 659788299,
               "url": "https://github.com/timescale/timescaledb/releases/download/2.31.0/fixture.zip"}
        with tempfile.TemporaryDirectory() as root, mock.patch.object(
                stage, "original_pin", return_value=pin):
            out = Path(root) / "staged"
            result = stage.original_stage("16", out, opener=FakeOpener(data))
            self.assertEqual((out / "timescaledb/setup.exe").read_bytes(),
                             b"stub Windows setup")
            self.assertEqual(result["sha256"], pin["sha256"])
            for key in ("publicGetAuthorized", "redistributionAuthorized",
                        "rightsAccepted", "producerAttestationVerified",
                        "signedAdmission", "publisherAuthorized"):
                self.assertIs(result[key], False)
            original = Path(root) / "fixture-original.zip"
            original.write_bytes(data)
            with self.assertRaises(ValueError):
                stage.extract_reviewed_zip(original, out)

    def test_missing_setup_and_all_unsafe_names_fail_before_extraction(self):
        variants = [
            [("timescaledb/lib/timescaledb.dll", b"x")],
            [("timescaledb/setup.exe", b"ok"), ("../escape.dll", b"x")],
            [("timescaledb/setup.exe", b"ok"), ("timescaledb/lib/C.dll", b"x"),
             ("timescaledb/lib/c.dll", b"y")],
            [("timescaledb/setup.exe", b"ok"), ("timescaledb/../../leak.dll", b"x")],
            [("timescaledb/setup.exe", b"ok"), ("C:/escape.dll", b"x")],
        ]
        with tempfile.TemporaryDirectory() as root:
            for i, entries in enumerate(variants):
                with self.subTest(index=i):
                    data = fixture(entries)
                    z = Path(root) / f"bad-{i}.zip"
                    out = Path(root) / f"dest-{i}"
                    z.write_bytes(data)
                    with self.assertRaises((ValueError, zipfile.BadZipFile)):
                        stage.extract_reviewed_zip(z, out)
                    self.assertFalse(out.exists())

    def test_corrupt_crc_fails_before_extraction(self):
        with tempfile.TemporaryDirectory() as root:
            data = fixture()
            value = bytearray(data)
            pos = value.index(b"stub DLL")
            value[pos] = ord("X")
            z = Path(root) / "corrupt.zip"
            out = Path(root) / "dest"
            z.write_bytes(value)
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                stage.extract_reviewed_zip(z, out)
            self.assertFalse(out.exists())

    def test_hash_and_length_mismatch_are_denied_before_stage(self):
        data = fixture()
        pin = {"pg": "18", "name": "fake.zip", "size": len(data),
               "sha256": hashlib.sha256(data).hexdigest(),
               "releaseId": 418582851, "assetId": 659790321,
               "url": "https://github.com/timescale/timescaledb/releases/download/2.31.0/fake.zip"}
        with tempfile.TemporaryDirectory() as root, mock.patch.object(
                stage, "original_pin", return_value=pin):
            for index, bad in enumerate((data[:-1], data[:-1] + b"z", data + b"extra")):
                dest = Path(root) / f"reject-{index}"
                with self.assertRaises(ValueError):
                    stage.original_stage("18", dest, opener=FakeOpener(bad))
                self.assertFalse(dest.exists())


if __name__ == "__main__":
    unittest.main()
