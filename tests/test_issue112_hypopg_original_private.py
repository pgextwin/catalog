"""Hostile synthetic original ZIP tests: no network, issuer, or public ZIP."""
import importlib.util
import io
import struct
import tempfile
import unittest
from pathlib import Path
import sys
import zipfile

PATH = Path(__file__).resolve().parents[1] / "scripts/issue112_hypopg_original_private.py"
spec = importlib.util.spec_from_file_location("hypopg_original_private", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def dll(machine=0x8664):
    buffer = bytearray(256)
    buffer[:2] = b"MZ"
    struct.pack_into("<I", buffer, 0x3C, 128)
    buffer[128:132] = b"PE\0\0"
    struct.pack_into("<H", buffer, 132, machine)
    return bytes(buffer)


class HypopgOriginalGuard(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "original.zip"

    def archive(self, names=None):
        files = names or [("hypopg.dll", dll()),
            ("hypopg.control", b"comment = 'test'"),
            ("hypopg--1.4.1.sql", b"SELECT 1;")]
        with zipfile.ZipFile(self.path, "w", zipfile.ZIP_DEFLATED) as z:
            for path, data in files:
                z.writestr(path, data)
        return self.path

    def test_pe_machine(self):
        module.pe_amd64(dll())
        with self.assertRaisesRegex(ValueError, "AMD64"):
            module.pe_amd64(dll(0x14c))

    def test_expected_bytes_deny_unpinned_fixture(self):
        # A well-formed synthetic ZIP is not the exact official original;
        # size guard always denies before any installation.
        self.archive()
        with self.assertRaisesRegex(ValueError, "ZIP size"):
            module.review(self.path, "16")

    def test_absolute_or_traversal_archive_denied(self):
        self.archive([("../hypopg.dll", dll()),
            ("hypopg.control", b"x"),
            ("hypopg--1.4.1.sql", b"y")])
        # Reuse original exact size check to force a correctly sized test payload
        # without allowing fake source bytes to prove actual original ZIP identity.
        original = module.PINS["16"]["bytes"]
        try:
            module.PINS["16"]["bytes"] = self.path.stat().st_size
            with self.assertRaisesRegex(ValueError, "unsafe/duplicate"):
                module.review(self.path, "16")
        finally:
            module.PINS["16"]["bytes"] = original

    def test_case_insensitive_duplicate_denied(self):
        self.archive([("hypopg.dll", dll()), ("HYPOPG.DLL", dll()),
            ("hypopg.control", b"x"), ("hypopg--1.4.1.sql", b"y")])
        original = module.PINS["16"]["bytes"]
        try:
            module.PINS["16"]["bytes"] = self.path.stat().st_size
            with self.assertRaisesRegex(ValueError, "unsafe/duplicate"):
                module.review(self.path, "16")
        finally:
            module.PINS["16"]["bytes"] = original

    def test_missing_sql_denied(self):
        self.archive([("hypopg.dll", dll()), ("hypopg.control", b"x")])
        original = module.PINS["16"]["bytes"]
        try:
            module.PINS["16"]["bytes"] = self.path.stat().st_size
            with self.assertRaisesRegex(ValueError, "member count|missing original"):
                module.review(self.path, "16")
        finally:
            module.PINS["16"]["bytes"] = original

    def test_bounded_identity_contract(self):
        self.assertEqual(set(module.PINS), {"14", "15", "16"})
        self.assertEqual(module.REPO, "HypoPG/hypopg")
        self.assertEqual(module.RELEASE_ID, 153113229)
        self.assertNotIn("17", module.PINS)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            module.review(self.archive(), "18")


if __name__ == "__main__":
    unittest.main()
