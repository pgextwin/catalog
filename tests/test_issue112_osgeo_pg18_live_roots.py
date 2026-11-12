#!/usr/bin/env python3
"""Offline hostile joins: no OSGeo ZIP fetch, publication or permissions."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue112_osgeo_pg18_live_roots import ROOT, ZIP_SHA, join_origins, unique_json

def fixture():
    root = r"C:\PostgreSQL\18"
    return {
        "pgMajor": "18", "pgRoot": root, "sampledProcessCount": 3,
        "source": "https://download-cache.osgeo.org/postgis/windows/pg18/" + ROOT + ".zip",
        "originalZipSha256": ZIP_SHA,
        "expectedRoots": [
            {"name": "postgis-3.dll", "member": ROOT + "/lib/postgis-3.dll", "sha256": "a" * 64},
            {"name": "libpgrouting-4.0.dll", "member": ROOT + "/lib/libpgrouting-4.0.dll", "sha256": "b" * 64},
        ],
        "observedModules": [
            {"name": "postgis-3.dll", "path": root + r"\lib\postgis-3.dll",
             "sha256": "a" * 64, "authenticodeStatus": "NotSigned"},
            {"name": "libpgrouting-4.0.dll", "path": root + r"\lib\libpgrouting-4.0.dll",
             "sha256": "b" * 64, "authenticodeStatus": "UnknownError"},
            {"name": "libcurl.dll", "path": root + r"\bin\libcurl.dll",
             "sha256": "c" * 64, "authenticodeStatus": "Valid"},
        ],
    }


class LiveRootsJoinTests(unittest.TestCase):
    def test_matching_both_original_root_bytes_are_observations_only(self):
        got = join_origins(fixture())
        self.assertEqual([x["name"] for x in got["rootDlls"]],
                         ["postgis-3.dll", "libpgrouting-4.0.dll"])
        self.assertTrue(got["allTwoServerRootOriginsObserved"])
        for key in ("allBundledDependenciesResolved", "dynamicLoadClosureVerified",
                    "componentRightsAndNoticesVerified", "producerSignedProvenanceVerified",
                    "independentOwnerAdmissionVerified", "publicGetAuthorized",
                    "mirrorAuthorized", "releaseAuthorized", "publisherAuthorized"):
            self.assertIs(got[key], False, key)

    def test_missing_wrong_origin_and_replaced_root_denied(self):
        for corruption in ("missing", "other-dir", "changed-hash", "duplicate",
                           "cross-major", "wrong-source", "wrong-bundle", "no-process"):
            f = fixture()
            if corruption == "missing":
                f["observedModules"].pop(1)
            elif corruption == "other-dir":
                f["observedModules"][0]["path"] = r"C:\attacker\postgis-3.dll"
            elif corruption == "changed-hash":
                f["observedModules"][1]["sha256"] = "0" * 64
            elif corruption == "duplicate":
                f["observedModules"].append(copy.deepcopy(f["observedModules"][0]))
            elif corruption == "cross-major":
                f["pgMajor"] = "17"
            elif corruption == "wrong-source":
                f["source"] = "https://evil.example/fake.zip"
            elif corruption == "wrong-bundle":
                f["originalZipSha256"] = "0" * 64
            else:
                f["sampledProcessCount"] = 0
            with self.assertRaises(ValueError, msg=corruption):
                join_origins(f)

    def test_tampered_member_and_unexpected_authorization_denied(self):
        for mutation in ("member", "pin", "public-get", "swapped-name", "traversal", "unc"):
            f = fixture()
            if mutation == "member":
                f["expectedRoots"][0]["member"] = "wrong.zip/lib/postgis-3.dll"
            elif mutation == "pin":
                f["expectedRoots"][0]["sha256"] = "g" * 64
            elif mutation == "public-get":
                f["observedModules"][0]["downloadAuthorized"] = True
            elif mutation == "swapped-name":
                f["observedModules"][0]["name"] = "libpgrouting-4.0.dll"
            elif mutation == "traversal":
                f["observedModules"][0]["path"] = r"C:\PostgreSQL\18\lib\..\postgis-3.dll"
            else:
                f["observedModules"][0]["path"] = r"\\evil\share\postgis-3.dll"
            with self.assertRaises(ValueError, msg=mutation):
                join_origins(f)

    def test_duplicate_json_key_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            unique_json([("pgMajor", "18"), ("pgMajor", "17")])


if __name__ == "__main__":
    unittest.main()
