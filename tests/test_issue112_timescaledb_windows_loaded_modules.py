"""Hostile offline tests: live module samples never confer distribution rights."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import issue112_timescaledb_windows_loaded_modules as mod

def sha(b):
    return hashlib.sha256(b).hexdigest()

def fixture():
    originals = []
    for name in sorted(mod.DLLS):
        originals.append({
            "path": "timescaledb/" + name, "sha256": sha(name.encode()),
            "analysis": "AMD64_PE32_PLUS_IMPORT_TABLES_PARSED",
            "nonbundledNameImports": ["postgres.exe", "libssl-3-x64.dll"],
        })
    stat = {
        "schemaVersion": "pgextwin-issue112-timescaledb-pe-imports-deny-only/v1",
        "state": "CANDIDATE_ONLY_NONPUBLISHING", "pgMajor": "18",
        "allImportTablesParsed": True, "publicGetAuthorized": False,
        "publisherAuthorized": False, "originalSha256": sha(b"original-zip"),
        "dllImportReceipts": originals,
        "unbundledImportTriage": [
            {"name": n, "referencedBy": sorted(x["path"] for x in originals),
             "resolvedOnExactTargetWindows": False}
            for n in ("libssl-3-x64.dll", "postgres.exe")
        ],
    }
    run = {"pgMajor": "18", "sampledProcessCount": 2, "modules": [
        {"name": "timescaledb.dll", "path": "C:\\PostgreSQL\\18\\lib\\timescaledb.dll",
         "sha256": sha(b"timescaledb.dll"), "authenticodeStatus": "NotSigned"},
        {"name": "libssl-3-x64.dll", "path": "C:\\PostgreSQL\\18\\bin\\libssl-3-x64.dll",
         "sha256": sha(b"openssl"), "authenticodeStatus": "Valid"},
    ]}
    return stat, run

class LiveModuleTests(unittest.TestCase):
    def test_exact_file_match_does_not_grant_rights_or_dependency_closure(self):
        original, observed = fixture()
        report = mod.join_receipts(original, observed, "18")
        self.assertTrue(next(x for x in report["timescaledbLoadedDlls"]
                             if x["name"] == "timescaledb.dll")
                        ["atLeastOneLoadedFileMatchesOriginalSha256"])
        loaded = {x["importName"]: x for x in report["nonbundledImports"]}
        self.assertTrue(loaded["libssl-3-x64.dll"]["observedAsLoadedModule"])
        self.assertFalse(loaded["postgres.exe"]["observedAsLoadedModule"])
        for gate in ("apiSetForwardingVerified", "unobservedDynamicLoadCoverageVerified",
                     "allDependenciesResolvedVerified", "licenseAndThirdPartyNoticesVerified",
                     "producerBuildToAssetSignatureVerified", "newSourceSpecificOwnerSignedAdmission",
                     "publicGetAuthorized", "mirrorAuthorized", "releaseAuthorized",
                     "publisherAuthorized"):
            self.assertIs(report[gate], False, gate)

    def test_hostile_inconsistent_receipts_are_rejected(self):
        a, b = fixture()
        cases = []
        x = copy.deepcopy(a); x["allImportTablesParsed"] = False; cases.append((x,b))
        x = copy.deepcopy(a); x["unbundledImportTriage"][0]["resolvedOnExactTargetWindows"] = True; cases.append((x,b))
        x = copy.deepcopy(a); x["dllImportReceipts"][0]["sha256"] = "f"*63; cases.append((x,b))
        x = copy.deepcopy(b); x["sampledProcessCount"] = 0; cases.append((a,x))
        x = copy.deepcopy(b); x["modules"][0]["sha256"] = sha(b"imposter"); cases.append((a,x))
        x = copy.deepcopy(b); x["modules"][0]["name"] = "bogus.dll"; cases.append((a,x))
        x = copy.deepcopy(b); x["modules"].append({**x["modules"][0], "sha256": sha(b"collision")}); cases.append((a,x))
        for original, runtime in cases:
            with self.subTest(n=cases.index((original,runtime))), self.assertRaises(ValueError):
                mod.join_receipts(original, runtime, "18")

    def test_missing_or_wrong_pg_host_fails_closed(self):
        a, b = fixture()
        with self.assertRaises(ValueError):
            mod.join_receipts(a,b,"17")
        b["modules"] = []
        with self.assertRaises(ValueError):
            mod.join_receipts(a,b,"18")

if __name__ == "__main__":
    unittest.main()
