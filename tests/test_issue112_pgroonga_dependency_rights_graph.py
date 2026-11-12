"""Offline hostile tests for PGroonga static name-to-rights graph."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue112_pgroonga_dependency_rights_graph import graph


PATHS = ["bin/libxxhash.dll", "bin/libgroonga.dll", "lib/pgroonga.dll"]


def fixtures():
    rights = {
        "pgMajor": 18, "version": "4.1.0",
        "expectedZipSha256": "a" * 64, "expectedZipBytes": 100,
        "licenseNoticeFiles": [
            {"path": "share/groonga/COPYING", "sha256": "d" * 64}
        ],
        "binaryMemberReceipts": [
            {"path": p, "bytes": 10, "sha256": chr(97 + i) * 64}
            for i, p in enumerate(PATHS)
        ],
    }
    imported = {
        "pgMajor": 18, "version": "4.1.0", "expectedZipSha256": "a" * 64,
        "expectedZipBytes": 100,
        "perBinaryImports": [
            {"path": PATHS[0], "analysis": "AMD64_PE32_PLUS",
             "staticImports": [], "delayImports": []},
            {"path": PATHS[1], "analysis": "AMD64_PE32_PLUS",
             "staticImports": ["libxxhash.dll"], "delayImports": ["kernel32.dll"]},
            {"path": PATHS[2], "analysis": "AMD64_PE32_PLUS",
             "staticImports": ["libgroonga.dll"], "delayImports": []},
        ],
    }
    return rights, imported


class GraphTests(unittest.TestCase):
    def test_transitive_missing_notice_propagates_without_authorizing(self):
        rights, imports = fixtures()
        out = graph(rights, imports)
        self.assertEqual(out["binaryMembers"], 3)
        self.assertEqual(out["missingNamedNoticeAtOwnBinary"],
                         ["bin/libxxhash.dll", "lib/pgroonga.dll"])
        by_path = {x["path"]: x for x in out["perBinaryGraph"]}
        self.assertEqual(by_path["lib/pgroonga.dll"]["staticReachableBundledBinaryPaths"],
                         ["bin/libgroonga.dll", "bin/libxxhash.dll"])
        self.assertIn("bin/libxxhash.dll",
                      by_path["lib/pgroonga.dll"]["staticReachableMissingNamedNoticeCandidates"])
        self.assertEqual(out["notBundledImportNames"][0]["name"], "kernel32.dll")
        for flag in ("allThirdPartyLicenseAndNoticeObligationsVerified",
                     "signedProducerSourceToBinaryAttestationVerified",
                     "independentOwnerSignedGetAdmission", "publicGetAuthorized",
                     "mirrorAuthorized", "releaseAuthorized", "publisherAuthorized"):
            self.assertIs(out[flag], False)
        self.assertIs(by_path["lib/pgroonga.dll"]["actualWindowsLoaderPathsVerified"], False)

    def test_changed_original_or_other_pg_major_rejected(self):
        rights, imports = fixtures()
        imports["expectedZipSha256"] = "b" * 64
        with self.assertRaises(ValueError):
            graph(rights, imports)
        rights, imports = fixtures()
        imports["pgMajor"] = 17
        with self.assertRaises(ValueError):
            graph(rights, imports)
        rights, imports = fixtures()
        with self.assertRaises(ValueError):
            graph(rights, imports, strict=True)

    def test_missing_duplicate_and_spoofed_paths_rejected(self):
        rights, imports = fixtures()
        imports["perBinaryImports"].pop()
        with self.assertRaises(ValueError):
            graph(rights, imports)
        rights, imports = fixtures()
        imports["perBinaryImports"][2]["path"] = PATHS[1]
        with self.assertRaises(ValueError):
            graph(rights, imports)
        rights, imports = fixtures()
        imports["perBinaryImports"][0]["path"] = "bin/libxxhash.dll.bak"
        with self.assertRaises(ValueError):
            graph(rights, imports)

    def test_untrusted_or_duplicate_import_names_rejected(self):
        for malformed in (["../../evil.dll"], ["LIBXXHASH.dll"],
                          ["libxxhash.dll", "libxxhash.dll"], [23]):
            rights, imports = fixtures()
            imports["perBinaryImports"][1]["staticImports"] = malformed
            with self.assertRaises((ValueError, TypeError)):
                graph(rights, imports)

    def test_ambiguous_basename_never_resolves_to_one_candidate(self):
        rights, imports = fixtures()
        original = rights["binaryMemberReceipts"][0].copy()
        original["path"] = "lib/libxxhash.dll"
        rights["binaryMemberReceipts"].append(original)
        imports["perBinaryImports"].append({
            "path": "lib/libxxhash.dll", "analysis": "AMD64_PE32_PLUS",
            "staticImports": [], "delayImports": []})
        out = graph(rights, imports)
        self.assertEqual(out["ambiguousBundledImportNames"][0]["name"], "libxxhash.dll")
        groonga = next(x for x in out["perBinaryGraph"] if x["path"] == PATHS[1])
        self.assertEqual(groonga["directBundledImportPathCandidates"], [])

    def test_non_pe_and_cycle_stay_unknown_and_bounded(self):
        rights, imports = fixtures()
        imports["perBinaryImports"][0]["staticImports"] = ["libgroonga.dll"]
        imports["perBinaryImports"][2] = {
            "path": PATHS[2], "analysis": "NOT_PARSED", "reason": "invalid PE"}
        out = graph(rights, imports)
        self.assertEqual(out["notParsedPeMembers"], [PATHS[2]])
        self.assertFalse(out["perBinaryGraph"][-1]["peImportParsed"])
        rights, imports = fixtures()
        imports["perBinaryImports"][0]["staticImports"] = ["libgroonga.dll"]
        out = graph(rights, imports)
        self.assertEqual(len(out["perBinaryGraph"]), 3)


if __name__ == "__main__":
    unittest.main()
