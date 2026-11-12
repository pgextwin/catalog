"""Negative tests for fixed-source, nonpublishing pg_show_plans latest pilot."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue112_pg_show_plans_native_pilot import (
    COMMIT, DENY, PINS, git_blob, verify_files, verify_source,
    msvc_patch_source, MSVC_OLD, MSVC_NEW,
)


class SourceGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_git_blob_matches_real_git_protocol(self):
        self.assertEqual(git_blob(b"hello\n"),
                         "ce013625030ba8dba906f756967f9e9ca394464a")
        self.assertNotEqual(git_blob(b"hello"), git_blob(b"hello\n"))

    def test_bounded_source_byte_pins_and_poisoned_unselected_file(self):
        (self.root / "LICENSE").write_bytes(b"correct")
        (self.root / "pg_show_plans.c").write_bytes(b"correct")
        pins = {n: git_blob(b"correct") for n in ("LICENSE", "pg_show_plans.c")}
        hashes = verify_files(self.root, pins)
        self.assertEqual(set(hashes), set(pins))
        (self.root / "LICENSE").write_bytes(b"poisoned")
        with self.assertRaisesRegex(ValueError, "Git blob mismatch"):
            verify_files(self.root, pins)

    def test_symlink_rejected_even_if_target_bytes_match(self):
        target = self.root / "real"
        target.write_bytes(b"correct")
        link = self.root / "LICENSE"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink requires Windows runner privilege")
        with self.assertRaisesRegex(ValueError, "linked source"):
            verify_files(self.root, {"LICENSE": git_blob(b"correct")})

    def test_unsafe_and_missing_pin_fail_closed(self):
        for pins in (
            {"../LICENSE": "0" * 40}, {"LICENSE": "z" * 40},
            {"LICENSE": git_blob(b"missing")}, {},
        ):
            with self.assertRaises(ValueError):
                verify_files(self.root, pins)

    def test_exact_compiler_only_patch_and_poisoned_original_denied(self):
        before = b"/* protected */\\n" + MSVC_OLD + b"\\n"
        patched = msvc_patch_source(before)
        self.assertIn(MSVC_NEW, patched)
        self.assertEqual(patched.count(MSVC_NEW), 1)
        self.assertEqual(patched.replace(MSVC_NEW, b""), before.replace(MSVC_OLD, b""))
        self.assertEqual(len(patched), len(before) + len(b"extern "))
        for bad in (b"", MSVC_OLD + MSVC_OLD, MSVC_NEW, b"Datum other(PG_FUNCTION_ARGS);"):
            with self.assertRaisesRegex(ValueError, "MSVC patch denied"):
                msvc_patch_source(bad)

    def test_untrusted_source_cannot_escalate_publishing(self):
        self.assertEqual(len(PINS), 7)
        self.assertEqual(len(COMMIT), 40)
        self.assertTrue(all(value is False for value in DENY.values()))
        self.assertFalse(DENY["publicGetAuthorized"])
        self.assertFalse(DENY["independentlySignedAdmission"])


if __name__ == "__main__":
    unittest.main()
