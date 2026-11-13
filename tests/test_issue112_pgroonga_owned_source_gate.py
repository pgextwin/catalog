"""Hostile offline checks for fixed source-owned PGroonga PG18 builder input."""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgroonga_owned_source_gate as gate

def fixture(tmp, *, entries=None):
    zip_path = Path(tmp) / gate.SOURCE[0]
    asc_path = Path(tmp) / gate.SIGNATURE[0]
    if entries is None:
        entries = {"groonga-16.1.3/CMakeLists.txt": b"project(groonga)\n",
                   "groonga-16.1.3/COPYING": b"license fixture\n"}
    with zipfile.ZipFile(zip_path, "w") as z:
        for name, content in entries.items():
            z.writestr(name, content)
    asc_path.write_bytes(b"signature fixture")
    source_pin = (gate.SOURCE[0], zip_path.stat().st_size,
                  hashlib.sha256(zip_path.read_bytes()).hexdigest())
    asc_pin = (gate.SIGNATURE[0], asc_path.stat().st_size,
               hashlib.sha256(asc_path.read_bytes()).hexdigest())
    return zip_path, asc_path, source_pin, asc_pin

class OwnedSourceGateTests(unittest.TestCase):
    def test_pinned_identities_and_enforced_denials(self):
        self.assertEqual(gate.PGROONGA_COMMIT, "47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc")
        self.assertEqual(gate.GROONGA_COMMIT, "9085dd417e5cd42cd8f1a367aaf24cfe45dd9f1f")
        self.assertEqual(gate.SOURCE[2], "ad892560511e5886dea2373101f0780e0a16394d30e5a20a8d3df12d7ef9e85d")
        self.assertEqual(gate.SIGNATURE[1], 833)
        self.assertEqual(set(gate.DENY.values()), {False})

    def test_private_receipt_has_no_admission(self):
        with tempfile.TemporaryDirectory() as temp:
            zip_path, asc, source, signature = fixture(temp)
            result = gate.inspect(zip_path, asc, source_pin=source, asc_pin=signature)
            self.assertEqual(result["pgMajor"], 18)
            self.assertEqual(result["archive"]["members"], 2)
            self.assertFalse(result["detachedSignatureCryptographicallyVerifiedByCaller"])
            self.assertTrue(all(result[key] is False for key in gate.DENY))

    def test_reject_mismatched_content_length_and_signature(self):
        with tempfile.TemporaryDirectory() as temp:
            z, a, sp, ap = fixture(temp)
            z.write_bytes(z.read_bytes() + b"modified")
            with self.assertRaisesRegex(ValueError, "exact filename, length or SHA256"):
                gate.inspect(z, a, source_pin=sp, asc_pin=ap)
            z, a, sp, ap = fixture(temp)
            a.write_bytes(b"forged")
            with self.assertRaisesRegex(ValueError, "exact filename, length or SHA256"):
                gate.inspect(z, a, source_pin=sp, asc_pin=ap)

    def test_reject_traversal_and_foreign_source(self):
        for bad in ("groonga-16.1.3/../outside", "../groonga-16.1.3/CMakeLists.txt",
                    "other/CMakeLists.txt", "groonga-16.1.3/C:\\evil"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as temp:
                z, a, sp, ap = fixture(temp, entries={
                    "groonga-16.1.3/CMakeLists.txt": b"cmake",
                    bad: b"pwn"})
                with self.assertRaisesRegex(ValueError, "source root or traversal|unsafe source ZIP path"):
                    gate.inspect(z, a, source_pin=sp, asc_pin=ap)

    def test_reject_duplicate_case_fold_and_missing_build_source(self):
        with tempfile.TemporaryDirectory() as temp:
            z, a, sp, ap = fixture(temp, entries={
                "groonga-16.1.3/CMakeLists.txt": b"a",
                "groonga-16.1.3/cmakelists.txt": b"b"})
            with self.assertRaisesRegex(ValueError, "duplicate"):
                gate.inspect(z, a, source_pin=sp, asc_pin=ap)
        with tempfile.TemporaryDirectory() as temp:
            z, a, sp, ap = fixture(temp, entries={"groonga-16.1.3/COPYING": b"x"})
            with self.assertRaisesRegex(ValueError, "CMake source entry"):
                gate.inspect(z, a, source_pin=sp, asc_pin=ap)

    def test_commit_pin_rejects_mismatched_sha(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(gate.subprocess, "run", return_value=mock.Mock(
                    returncode=0, stdout="0"*40)):
                with self.assertRaisesRegex(ValueError, "commit not fixed"):
                    gate.source_commit(temp)
            with mock.patch.object(gate.subprocess, "run", return_value=mock.Mock(
                    returncode=0, stdout=gate.PGROONGA_COMMIT+"\n")):
                self.assertEqual(gate.source_commit(temp), gate.PGROONGA_COMMIT)

    def test_no_runtime_config_can_upgrade_denial(self):
        with tempfile.TemporaryDirectory() as temp:
            z, a, sp, ap = fixture(temp)
            receipt = gate.inspect(z, a, source_pin=sp, asc_pin=ap)
            mutated = deepcopy(receipt)
            mutated["publisherAuthorized"] = True
            self.assertNotEqual(mutated["publisherAuthorized"], gate.DENY["publisherAuthorized"])
            self.assertFalse(receipt["allLicenseNoticeObligationsAccepted"])

if __name__ == "__main__":
    unittest.main()
