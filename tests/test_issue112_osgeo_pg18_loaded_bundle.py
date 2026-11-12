#!/usr/bin/env python3
"""Fail-closed, offline hostile receipts for OSGeo PG18 sampled dependencies."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue112_osgeo_pg18_loaded_bundle import ROOT, SOURCE, ZIP_SHA, audit_loaded_bundle

BASE = r"C:\Program Files\PostgreSQL\18"


def fixture():
    return {
        "pgMajor": "18", "originalZipSha256": ZIP_SHA, "source": SOURCE,
        "pgRoot": BASE, "sampledProcessCount": 2,
        "expectedServerMembers": [
            {"member": ROOT + "/lib/postgis-3.dll", "sha256": "a" * 64, "bytes": 100},
            {"member": ROOT + "/lib/libpgrouting-4.0.dll", "sha256": "b" * 64, "bytes": 200},
            {"member": ROOT + "/bin/libcurl.dll", "sha256": "c" * 64, "bytes": 300},
            {"member": ROOT + "/bin/libgeos_c.dll", "sha256": "e" * 64, "bytes": 400},
        ],
        "observedModules": [
            {"name": "postgis-3.dll", "path": BASE + r"\lib\postgis-3.dll", "sha256": "a" * 64},
            {"name": "libpgrouting-4.0.dll", "path": BASE + r"\lib\libpgrouting-4.0.dll", "sha256": "b" * 64},
            {"name": "libcurl.dll", "path": BASE + r"\bin\libcurl.dll", "sha256": "d" * 64},
            {"name": "libgeos_c.dll", "path": BASE + r"\bin\libgeos_c.dll", "sha256": "e" * 64},
            {"name": "postgres-host.dll", "path": BASE + r"\bin\postgres-host.dll", "sha256": "f" * 64},
        ],
        "preservedHostDll": {
            "name": "libcurl.dll", "path": BASE + r"\bin\libcurl.dll", "sha256": "d" * 64},
    }


class TestLoadedBundle(unittest.TestCase):
    def test_original_matches_and_host_substitution_are_separate(self):
        report = audit_loaded_bundle(fixture())
        self.assertEqual(report["sampledExactOriginalMemberMatches"], 3)
        self.assertEqual(report["sampledPreservedEdbHostDlls"], 1)
        self.assertEqual(report["sampledOtherPgHostDllsNotInOriginal"], 1)
        self.assertEqual(report["sampledUnverifiedOriginalPathMismatches"], 0)
        self.assertFalse(report["publicGetAuthorized"])
        self.assertFalse(report["transitiveDependencyClosureVerified"])
        self.assertFalse(report["allComponentRightsAndNoticesVerified"])
        self.assertFalse(report["producerSourceToZipSigned"])

    def test_wrong_pin_member_path_or_permission_denied(self):
        variants = [
            lambda x: x.update(pgMajor="17"),
            lambda x: x.update(originalZipSha256="0" * 64),
            lambda x: x.update(source="https://example.invalid/other.zip"),
            lambda x: x.update(publicGetAuthorized=True),
            lambda x: x["expectedServerMembers"][0].update(member=ROOT + "/lib/../postgis-3.dll"),
            lambda x: x["expectedServerMembers"][0].update(sha256="0" * 64),
            lambda x: x["expectedServerMembers"].append(copy.deepcopy(x["expectedServerMembers"][0])),
            lambda x: x["observedModules"].append(copy.deepcopy(x["observedModules"][0])),
            lambda x: x["observedModules"][0].update(path=r"C:\Other\lib\postgis-3.dll"),
            lambda x: x["observedModules"][0].update(sha256="1" * 64),
            lambda x: x["observedModules"][0].update(name="libpgrouting-4.0.dll"),
            lambda x: x["observedModules"][0].update(path=r"\\evil\share\postgis-3.dll"),
            lambda x: x["observedModules"][0].update(path=BASE + r"\lib\..\lib\postgis-3.dll"),
            lambda x: x["preservedHostDll"].update(path=BASE + r"\lib\libcurl.dll"),
            lambda x: x["preservedHostDll"].update(sha256="0" * 64),
            lambda x: x.update(sampledProcessCount=0),
            lambda x: x["expectedServerMembers"].pop(0),
        ]
        for mutate in variants:
            data = fixture()
            mutate(data)
            with self.subTest(mutation=str(mutate)), self.assertRaises(ValueError):
                audit_loaded_bundle(data)

    def test_nonroot_mismatch_remains_unverified(self):
        data = fixture()
        data["observedModules"][3]["sha256"] = "0" * 64
        report = audit_loaded_bundle(data)
        self.assertEqual(report["sampledUnverifiedOriginalPathMismatches"], 1)
        self.assertFalse(report["transitiveDependencyClosureVerified"])
        self.assertFalse(report["publicGetAuthorized"])


if __name__ == "__main__":
    unittest.main()
