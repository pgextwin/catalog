#!/usr/bin/env python3
"""Offline hostile ZIP and stream tests; never perform a network GET."""
import hashlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_http_original_receipts as audit


def pe64(machine=0x8664):
    data = bytearray(256)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<H", data, 132, machine)
    return bytes(data)


def make_zip(path, extra=None):
    items = {
        "share/extension/http.control": b"default_version = '1.7.1'",
        "share/extension/http--1.7.1.sql": b"-- SQL",
        "lib/http.dll": pe64(),
    }
    if extra:
        items.update(extra)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in items.items():
            archive.writestr(name, data)


class OriginalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "original.zip"

    def test_exact_member_receipts_are_nonpublishing(self):
        make_zip(self.path, {"rights/LICENSE": b"candidate, not clearance"})
        result = audit.inspect_archive(self.path)
        self.assertEqual(result["httpDllPath"], "lib/http.dll")
        self.assertEqual(result["rightsNamedPaths"], ["rights/LICENSE"])
        self.assertTrue(result["amd64PeHeaderVerified"])
        self.assertTrue(result["zipCrcVerified"])

    def test_hash_real_stream(self):
        value = b"PK" + b"\x00" * 42
        size, digest = audit.copy_stream(io.BytesIO(value), self.path)
        self.assertEqual(size, len(value))
        self.assertEqual(digest, hashlib.sha256(value).hexdigest())

    def test_excess_bytes_denied(self):
        with self.assertRaisesRegex(ValueError, "size cap"):
            audit.copy_stream(io.BytesIO(b"x" * 30), self.path, limit=25)

    def test_truncated_stream_denied(self):
        with self.assertRaisesRegex(ValueError, "too short"):
            audit.copy_stream(io.BytesIO(b"PK"), self.path)

    def test_redirect_denied(self):
        with self.assertRaisesRegex(ValueError, "redirect prohibited"):
            audit.DenyRedirect().redirect_request(
                None, None, 302, "Moved", {}, "https://mirror.example/asset")

    def test_traversal_denied(self):
        make_zip(self.path, {"../escape": b"no"})
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            audit.inspect_archive(self.path)

    def test_case_collision_denied(self):
        make_zip(self.path, {"LIB/HTTP.DLL": pe64()})
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            audit.inspect_archive(self.path)

    def test_symlink_denied(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("share/extension/http.control", b"present")
            archive.writestr("lib/http.dll", pe64())
            link = zipfile.ZipInfo("lib/link")
            link.create_system = 3
            link.external_attr = 0o120777 << 16
            archive.writestr(link, b"bad")
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            audit.inspect_archive(self.path)

    def test_missing_control_denied(self):
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr("lib/http.dll", pe64())
        with self.assertRaisesRegex(ValueError, "http.control"):
            audit.inspect_archive(self.path)

    def test_wrong_arch_denied(self):
        make_zip(self.path, {"lib/http.dll": pe64(0x14c)})
        with self.assertRaisesRegex(ValueError, "not verified AMD64"):
            audit.inspect_archive(self.path)

    def test_expansion_ratio_denied(self):
        make_zip(self.path, {"untrusted.txt": b"A" * 1000000})
        with self.assertRaisesRegex(ValueError, "Overexpanded"):
            audit.inspect_archive(self.path)

    def test_unknown_major_denied_without_download(self):
        with self.assertRaisesRegex(ValueError, "Unsupported PostgreSQL major"):
            audit.observe("19")

    def test_only_14_through_18_with_exact_origins(self):
        self.assertEqual(set(audit.CANDIDATES), {"14", "15", "16", "17", "18"})
        self.assertEqual(audit.ORIGIN, "https://www.postgresonline.com/downloads/")


if __name__ == "__main__":
    unittest.main()
