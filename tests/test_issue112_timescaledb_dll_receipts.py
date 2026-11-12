"""Adversarial offline PE/member tests; no source GET or authority."""
import hashlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_timescaledb_dll_receipts as audit


def pe_bytes(machine=0x8664, magic=0x20B):
    b = bytearray(512)
    b[:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", b, 0x84, machine)
    struct.pack_into("<H", b, 0x94, 0xF0)
    struct.pack_into("<H", b, 0x98, magic)
    return bytes(b)


def zip_bytes(members=None):
    s = io.BytesIO()
    with zipfile.ZipFile(s, "w") as z:
        for name, body in (members if members is not None else [
            ("timescale/lib/timescaledb.dll", pe_bytes()),
            ("timescale/lib/timescaledb-tsl.dll", pe_bytes()),
            ("timescale/lib/timescaledb-loader.dll", pe_bytes()),
        ]):
            z.writestr(name, body)
    return s.getvalue()


class Response(io.BytesIO):
    def geturl(self):
        return "https://release-assets.githubusercontent.com/fixture"


class Opener:
    def __init__(self, data):
        self.data = data

    def open(self, request, timeout=None):
        return Response(self.data)


class DllEvidenceTests(unittest.TestCase):
    def test_valid_three_pe_files_are_exact_path_receipts_not_rights(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "original.zip"
            p.write_bytes(zip_bytes())
            v = audit.dll_receipts(p)
        self.assertEqual(len(v["dllMembers"]), 3)
        for row in v["dllMembers"]:
            self.assertEqual(row["peObservation"], "AMD64_PE32_PLUS_HEADER_ONLY")
            self.assertEqual(row["actualSourceComponent"], "UNVERIFIED")
            self.assertEqual(row["componentLicenseAndNotice"], "UNVERIFIED")
            self.assertEqual(row["producerSourceToBinaryProvenance"], "UNVERIFIED")
            self.assertRegex(row["sha256"], r"^[a-f0-9]{64}$")

    def test_invalid_machine_optional_header_and_traversal_fail_closed(self):
        variants = (
            [("one.dll", pe_bytes(0x14C)), ("two.dll", pe_bytes()), ("three.dll", pe_bytes())],
            [("one.dll", pe_bytes(magic=0x10B)), ("two.dll", pe_bytes()), ("three.dll", pe_bytes())],
            [("../one.dll", pe_bytes()), ("two.dll", pe_bytes()), ("three.dll", pe_bytes())],
            [("one.dll", pe_bytes()), ("ONE.dll", pe_bytes()), ("three.dll", pe_bytes())],
            [("one.dll", pe_bytes()), ("two.dll", pe_bytes())],
        )
        with tempfile.TemporaryDirectory() as tmp:
            for i, members in enumerate(variants):
                p = Path(tmp) / f"bad-{i}.zip"
                p.write_bytes(zip_bytes(members))
                with self.subTest(i=i), self.assertRaises(ValueError):
                    audit.dll_receipts(p)

    def test_fake_url_bytes_rejected_before_receipts(self):
        data = zip_bytes()
        pin = {"name": "pinned.zip", "url": "https://github.com/example/test.zip",
               "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
               "assetId": 123}
        with mock.patch.object(audit, "original_pin", return_value=pin):
            with self.assertRaises(ValueError):
                audit.audit("18", opener=Opener(data[:-1]))
            with self.assertRaises(ValueError):
                audit.audit("18", opener=Opener(data + b"tampered"))

    def test_synthetic_success_does_not_promote_get_or_publisher(self):
        data = zip_bytes()
        pin = {"name": "pinned.zip", "url": "https://github.com/example/test.zip",
               "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
               "assetId": 123}
        with mock.patch.object(audit, "original_pin", return_value=pin):
            r = audit.audit("17", opener=Opener(data))
        self.assertEqual(r["originalSha256"], pin["sha256"])
        self.assertEqual(r["state"], "CANDIDATE_ONLY_NONPUBLISHING")
        for field in ("allBinaryComponentLicensesVerified", "completeNoticesVerified",
                      "dynamicDependenciesVerified", "producerBuildToAssetSignatureVerified",
                      "newSourceSpecificSignedAdmission", "publicGetAuthorized",
                      "mirrorAuthorized", "releaseAuthorized", "publisherAuthorized"):
            self.assertIs(r[field], False, field)


if __name__ == "__main__":
    unittest.main()
