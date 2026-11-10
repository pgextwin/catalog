"""Offline hostile tests; rights receipts are never public-download admission."""
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgroonga_rights_audit as audit

def make(path, *, extra=None, remove=()):
    members = {
        "lib/pgroonga.dll": b"MZ:pgroonga",
        "bin/libgroonga.dll": b"MZ:groonga",
        "share/extension/pgroonga.control": b"default_version=4.1.0",
        "COPYING": b"PostgreSQL license",
        "share/LICENSE.txt": b"LGPL-2.1",
    }
    members.update(extra or {})
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            if name not in remove:
                z.writestr(name, data)

class ReceiptTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "original.zip"

    def report(self):
        return audit.audit_members(self.path, 18, require_pin=False)

    def test_never_authorizes_and_hashes_individual_binaries(self):
        make(self.path)
        result = self.report()
        self.assertEqual(result["binaryMemberCount"], 2)
        self.assertEqual(result["licenseNoticeCandidatesCount"], 2)
        for key in ("licenseNoticeClosureVerified", "thirdPartyComponentVersionsVerified",
                    "exactSourceToReleaseBinaryAttestationVerified",
                    "targetWindowsDynamicDependenciesVerified", "redistributionAuthorized",
                    "independentSigstoreAdmissionVerified", "publicGetAuthorized",
                    "mirrorAuthorized", "publisherAuthorized"):
            self.assertIs(result[key], False, key)
        row = next(x for x in result["binaryMemberReceipts"] if x["path"] == "bin/libgroonga.dll")
        self.assertEqual(row["sha256"], hashlib.sha256(b"MZ:groonga").hexdigest())
        self.assertFalse(row["componentLicenseNoticeVerified"])

    def test_similarly_named_binary_does_not_inherit_license(self):
        make(self.path, extra={"bin/copyright-vendor.dll": b"MZ:other"})
        row = next(x for x in self.report()["binaryMemberReceipts"]
                   if x["path"].endswith("copyright-vendor.dll"))
        self.assertFalse(row["exactProducerProvenanceVerified"])

    def test_duplicate_basename_retains_separate_receipts(self):
        make(self.path, extra={"lib/libgroonga.dll": b"MZ:distinct"})
        result = self.report()
        self.assertEqual(len(result["duplicateBinaryBasenames"]["libgroonga.dll"]), 2)
        self.assertEqual(len({x["sha256"] for x in result["binaryMemberReceipts"]
                              if x["path"].endswith("libgroonga.dll")}), 2)

    def test_traversal_duplicate_and_colon_rejected(self):
        for name in ("../escape.dll", "BIN/LIBGROONGA.DLL", "bin/evil:thing.dll"):
            make(self.path, extra={name: b"MZ"})
            with self.assertRaises(ValueError):
                self.report()

    def test_missing_extension_payload_rejected(self):
        for name in ("lib/pgroonga.dll", "share/extension/pgroonga.control"):
            make(self.path, remove=(name,))
            with self.assertRaises(ValueError):
                self.report()

    def test_empty_and_oversized_license_rejected(self):
        for data in (b"", b"X" * (audit.MAX_LICENSE + 1)):
            make(self.path, extra={"share/NOTICE": data})
            with self.assertRaises(ValueError):
                self.report()

    def test_exact_production_pin_required(self):
        make(self.path)
        with self.assertRaises(ValueError):
            audit.audit_members(self.path, 18)
        self.assertEqual(audit.PINS[18][0], 53826667)
        self.assertEqual(len(audit.PINS[18][1]), 64)

if __name__ == "__main__":
    unittest.main()
