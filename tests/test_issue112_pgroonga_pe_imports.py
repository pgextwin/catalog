"""Offline tests: original PGroonga PE imports never become GET authorization."""
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgroonga_pe_imports as probe

def archive(path, *, extra=None):
    entries = {
        "bin/libgroonga.dll": b"MZ-invalid-pe",
        "lib/pgroonga.dll": b"MZ-invalid-pe",
        "share/extension/pgroonga.control": b"default_version = 4.1.0",
        "share/pgroonga/COPYING": b"license",
    }
    entries.update(extra or {})
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)

class ImportReceiptTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "original.zip"

    def test_unparsed_binary_stays_unverified(self):
        archive(self.path)
        report = probe.inspect_archive(self.path, 18, verify_pin=False)
        self.assertEqual(report["binaryMemberCount"], 2)
        self.assertEqual(report["parsedPeCount"], 0)
        self.assertEqual(len(report["nonparsedBinaryMembers"]), 2)
        for flag in ("completeRuntimeDependenciesVerified", "actualTargetWindowsDllResolutionVerified",
                     "dynamicLoadLibraryDependenciesVerified", "componentLicenseAndNoticeClosureVerified",
                     "exactProducerProvenanceVerified", "independentSignedGetAdmission",
                     "publicGetAuthorized", "mirrorAuthorized", "publisherAuthorized"):
            self.assertIs(report[flag], False, flag)

    def test_absent_import_keeps_exact_requester(self):
        rows = [
            {"path": "lib/pgroonga.dll", "analysis": "AMD64_PE32_PLUS",
             "staticImports": ["libgroonga.dll", "unknown.dll"],
             "delayImports": ["unknown.dll"]},
            {"path": "bin/libgroonga.dll", "analysis": "AMD64_PE32_PLUS",
             "staticImports": ["unknown.dll"], "delayImports": []},
        ]
        triage = probe.import_triage(rows, {"pgroonga.dll", "libgroonga.dll"})
        self.assertEqual(triage, [{"name": "unknown.dll",
                                  "requesters": ["bin/libgroonga.dll", "lib/pgroonga.dll"],
                                  "targetWindowsDllResolutionVerified": False}])

    def test_unparsed_cannot_add_invented_imports(self):
        rows = [{"path": "lib/pgroonga.dll", "analysis": "NOT_PARSED", "reason": "bad header"}]
        self.assertEqual(probe.import_triage(rows, set()), [])

    def test_duplicate_basename_not_accepted_as_loader_resolution(self):
        archive(self.path, extra={"lib/libgroonga.dll": b"MZ-second"})
        report = probe.inspect_archive(self.path, 18, verify_pin=False)
        self.assertEqual(len(report["ambiguousBundledBasenames"]["libgroonga.dll"]), 2)
        self.assertFalse(report["actualTargetWindowsDllResolutionVerified"])

    def test_pin_cannot_be_omitted_in_live_path(self):
        archive(self.path)
        with self.assertRaises(ValueError):
            probe.inspect_archive(self.path, 18)

if __name__ == "__main__":
    unittest.main()
