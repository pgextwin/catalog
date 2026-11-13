"""Offline hostile PE import-table fixtures. No provider download in this test."""
from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import issue112_pglogical_pe_import_inventory as audit


def fixture(module=b"KERNEL32.dll", *, delay=False):
    buf = bytearray(2048)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3c, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 0x84, 0x8664)
    struct.pack_into("<H", buf, 0x86, 1)       # sections
    struct.pack_into("<H", buf, 0x94, 0xf0)    # optional header length
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x20b)
    struct.pack_into("<I", buf, opt + 108, 16)
    struct.pack_into("<II", buf, opt + 112 + 8, 0x1010, 40)
    section = opt + 0xf0
    buf[section:section + 8] = b".rdata\x00\x00"
    struct.pack_into("<I", buf, section + 8, 0x600)
    struct.pack_into("<I", buf, section + 12, 0x1000)
    struct.pack_into("<I", buf, section + 16, 0x600)
    struct.pack_into("<I", buf, section + 20, 0x200)
    struct.pack_into("<I", buf, 0x210 + 12, 0x1070)
    buf[0x270:0x270 + len(module) + 1] = module + b"\x00"
    if delay:
        struct.pack_into("<II", buf, opt + 112 + 13 * 8, 0x1100, 64)
        struct.pack_into("<I", buf, 0x300, 1)       # RVA not VA descriptor
        struct.pack_into("<I", buf, 0x304, 0x1180)
        buf[0x380:0x38c] = b"WS2_32.dll\x00\x00"
    return bytes(buf)


class OriginalPEImportTests(unittest.TestCase):
    def test_import_and_delay_name_inventory(self):
        self.assertEqual(audit.pe_imports(fixture()),
                         {"static": ["kernel32.dll"], "delay": []})
        self.assertEqual(audit.pe_imports(fixture(delay=True)),
                         {"static": ["kernel32.dll"], "delay": ["ws2_32.dll"]})

    def test_architecture_and_bounds_fail_closed(self):
        for mutation in (
            lambda b: b.__setitem__(slice(0x84, 0x86), b"\x4c\x01"),
            lambda b: struct.pack_into("<I", b, 0x210 + 12, 0x999999),
            lambda b: struct.pack_into("<I", b, 0x188 + 20, 0xdeadbeef),
            lambda b: struct.pack_into("<I", b, 0x98 + 108, 40),
            lambda b: struct.pack_into("<II", b, 0x98 + 112 + 8, 0x1010, 0),
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                data = bytearray(fixture())
                mutation(data)
                audit.pe_imports(bytes(data))

    def test_path_and_unicode_name_rejected(self):
        for name in (b"../evil.dll", b"C:\\evil.dll", b"evil/evil.dll",
                     b"bad library.dll", b"\xff.dll", b"evil.so"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                audit.pe_imports(fixture(module=name))

    def test_delay_va_mode_rejected(self):
        data = bytearray(fixture(delay=True))
        struct.pack_into("<I", data, 0x300, 0)
        with self.assertRaises(ValueError):
            audit.pe_imports(bytes(data))

    def test_no_authorization_or_publish_from_imports(self):
        workflow = (ROOT / ".github/workflows/issue112-pglogical-pe-inventory.yml").read_text()
        self.assertIn("pull_request:", workflow)
        self.assertIn("contents: read", workflow)
        for forbidden in ("workflow_dispatch:", "contents: write", "id-token: write",
                          "upload-artifact", "create-release", "schedule:"):
            self.assertNotIn(forbidden, workflow)
        with patch.dict("os.environ", {"GITHUB_ACTIONS": "false"}, clear=True):
            with self.assertRaises(ValueError):
                audit.audit_all()


if __name__ == "__main__":
    unittest.main()
