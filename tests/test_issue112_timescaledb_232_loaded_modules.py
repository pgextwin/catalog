"""2.32.0 hostile live-module tests; no publishing or GET authority."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import issue112_timescaledb_windows_loaded_modules as mod
from issue112_timescaledb_pe_imports import latest_original_pin


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture(pg="18"):
    pin = latest_original_pin(pg)
    members = []
    for name in sorted(mod.dll_names("2.32.0")):
        members.append({
            "path": "timescaledb/" + name,
            "sha256": sha(name.encode()),
            "analysis": "AMD64_PE32_PLUS_IMPORT_TABLES_PARSED",
            "nonbundledNameImports": ["libssl-3-x64.dll", "postgres.exe"],
        })
    static = {
        "schemaVersion": "pgextwin-issue112-timescaledb-pe-imports-deny-only/v1",
        "state": "CANDIDATE_ONLY_NONPUBLISHING",
        "pgMajor": pg, "releaseTag": "2.32.0",
        "releaseId": pin["releaseId"],
        "assetId": pin["assetId"],
        "originalBytes": pin["size"],
        "originalSha256": pin["sha256"],
        "allImportTablesParsed": True,
        "publicGetAuthorized": False,
        "publisherAuthorized": False,
        "dllImportReceipts": members,
        "unbundledImportTriage": [
            {"name": name,
             "referencedBy": sorted(x["path"] for x in members),
             "resolvedOnExactTargetWindows": False}
            for name in ("libssl-3-x64.dll", "postgres.exe")
        ],
    }
    runtime = {
        "pgMajor": pg, "releaseVersion": "2.32.0",
        "sampledProcessCount": 2,
        "modules": [
            {"name": "timescaledb.dll",
             "path": "C:\\PostgreSQL\\" + pg + "\\lib\\timescaledb.dll",
             "sha256": sha(b"timescaledb.dll"),
             "authenticodeStatus": "NotSigned"},
            {"name": "libssl-3-x64.dll",
             "path": "C:\\PostgreSQL\\" + pg + "\\bin\\libssl-3-x64.dll",
             "sha256": sha(b"openssl"),
             "authenticodeStatus": "Valid"},
        ],
    }
    return static, runtime


class Live232Tests(unittest.TestCase):
    def test_all_major_exact_original_receipts_never_promote(self):
        for pg in ("16", "17", "18"):
            with self.subTest(pg=pg):
                static, runtime = fixture(pg)
                report = mod.join_receipts(static, runtime, pg, version="2.32.0")
                self.assertEqual(report["releaseTag"], "2.32.0")
                self.assertEqual(report["originalZipSha256"], static["originalSha256"])
                self.assertTrue(any(x["atLeastOneLoadedFileMatchesOriginalSha256"]
                                    for x in report["timescaledbLoadedDlls"]))
                for denied in ("apiSetForwardingVerified",
                               "allDependenciesResolvedVerified",
                               "licenseAndThirdPartyNoticesVerified",
                               "producerBuildToAssetSignatureVerified",
                               "newSourceSpecificOwnerSignedAdmission",
                               "publicGetAuthorized", "mirrorAuthorized",
                               "releaseAuthorized", "publisherAuthorized"):
                    self.assertIs(report[denied], False, denied)

    def test_cross_version_original_pins_and_permission_tampering_fail_closed(self):
        static, runtime = fixture()
        cases = []
        x = copy.deepcopy(static); x["releaseTag"] = "2.31.0"; cases.append((x, runtime))
        x = copy.deepcopy(static); x["originalSha256"] = sha(b"old-original"); cases.append((x, runtime))
        x = copy.deepcopy(static); x["originalBytes"] -= 1; cases.append((x, runtime))
        x = copy.deepcopy(static); x["assetId"] = latest_original_pin("17")["assetId"]; cases.append((x, runtime))
        x = copy.deepcopy(static); x["dllImportReceipts"][0]["path"] = "timescaledb/timescaledb-2.31.0.dll"; cases.append((x, runtime))
        x = copy.deepcopy(static); x["publicGetAuthorized"] = True; cases.append((x, runtime))
        x = copy.deepcopy(static); x["unbundledImportTriage"][0]["resolvedOnExactTargetWindows"] = True; cases.append((x, runtime))
        x = copy.deepcopy(runtime); x["releaseVersion"] = "2.31.0"; cases.append((static, x))
        x = copy.deepcopy(runtime); x["modules"][0]["sha256"] = sha(b"impostor"); cases.append((static, x))
        for index, (a, b) in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                mod.join_receipts(a, b, "18", version="2.32.0")

    def test_wrong_major_and_unreviewed_version_fail_closed(self):
        static, runtime = fixture()
        for version in ("2.33.0", "2.31", "", "../2.32.0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                mod.join_receipts(static, runtime, "18", version=version)
        with self.assertRaises(ValueError):
            mod.join_receipts(static, runtime, "17", version="2.32.0")
        with self.assertRaises(ValueError):
            mod.join_receipts(static, runtime, "18")
        with self.assertRaises(ValueError):
            mod.join_receipts(static, runtime, "14", version="2.32.0")


if __name__ == "__main__":
    unittest.main()
