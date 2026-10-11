#!/usr/bin/env python3
"""Fail-closed Wave 3 Catalog record transformation tests; no network."""
import importlib.util
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[1]/"scripts"/"propose_verified_wave3.py"
spec=importlib.util.spec_from_file_location("verified_wave3",path)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class Wave3Fixture(unittest.TestCase):
    def setUp(self):
        mod.EXT="pg_partman";mod.REPOSITORY="pgextwin/pg_partman"
        self.manifest={"name":"pg_partman","upstream":{"repository":"pgpartman/pg_partman","version":"5.5.0","ref":"v5.5.0"},
                       "postgresql":{"majors":[14,15,16,17,18]}}
        self.contract={"contractVersion":2,"extension":"pg_partman",
                       "runtimeRequirements":{"preload":"none","backgroundWorker":False},"testSetup":{"preload":"none","backgroundWorker":False,"settings":[]},"coverage":{"upgrade":"not-covered","backgroundWorker":"not-applicable"},
                       "functionalScenarios":[{"id":"routing","description":"routing","evidence":["sql-result"]}]}
        self.old={"schemaVersion":2,"name":"pg_partman","repository":"pgextwin/pg_partman",
                  "upstream":{"version":"5.5.0"},"latest":{},"postgresql":{},
                  "runtime":{"requirements":{}},"capabilities":{},"capabilitiesSource":{}}
        self.rel={"tag_name":"v5.5.0-windows.1","published_at":"2026-10-10T15:00:00Z",
                  "draft":False,"prerelease":False}
        self.assets={"SHA256SUMS.txt":{"name":"SHA256SUMS.txt","state":"uploaded"}}
        for major in range(14,19):
            stem="pg_partman-v5.5.0-pg"+str(major)+"-windows-x64"
            for ext in (".zip",".spdx.json",".vulnerabilities.json"):
                name=stem+ext;self.assets[name]={"name":name,"state":"uploaded"}
        self.sums={x:"f"*64 for x in self.assets if x!="SHA256SUMS.txt"}

    def record(self,**overrides):
        return mod.update_record(self.old,self.rel,self.manifest,self.contract,
                                 self.assets,self.sums,"a"*40,required_majors=[14,15,16,17,18])

    def test_upstream_asset_reference_conventions(self):
        for extension,version,ref in [
            ("pg_partman","5.5.0","v5.5.0"),
            ("orafce","4.16.13","VERSION_4_16_13"),
            ("pg_stat_monitor","2.4.0","2.4.0")
        ]:
            with self.subTest(extension=extension):
                mod.EXT=extension
                self.assertEqual(mod.upstream_ref_for_version(version),ref)
                self.assertEqual(mod.asset_stem(version,17),f"{extension}-{ref}-pg17-windows-x64")
        mod.EXT="pg_partman"

    def test_sql_only_release_does_not_claim_bgw(self):
        out=self.record()
        self.assertEqual(out["runtime"]["sharedPreloadLibraries"],[])
        self.assertFalse(out["runtime"]["requirements"]["backgroundWorker"])

    def test_optin_bgw_release_updates_legacy_preload_field(self):
        self.contract["runtimeRequirements"]["backgroundWorker"]=True
        self.contract["runtimeRequirements"]["preload"]="optional"
        self.contract["testSetup"]={"preload":"shared","backgroundWorker":True,"settings":[]}
        self.contract["coverage"]["backgroundWorker"]="covered"
        out=self.record()
        self.assertEqual(out["runtime"]["sharedPreloadLibraries"],["pg_partman_bgw"])
        self.assertEqual(out["capabilities"]["coverage"]["backgroundWorker"],"covered")

    def test_unverified_bgw_contract_is_rejected(self):
        self.contract["runtimeRequirements"]["backgroundWorker"]=True
        self.contract["runtimeRequirements"]["preload"]="optional"
        with self.assertRaises(mod.UnsafeCatalog):self.record()

    def test_source_ref_mismatch_is_rejected(self):
        self.manifest["upstream"]["ref"]="v5.4.0"
        with self.assertRaises(mod.UnsafeCatalog):self.record()

    def test_five_major_complete_record(self):
        out=self.record()
        self.assertEqual(len(out["postgresql"]),5)
        self.assertEqual(out["latest"]["releaseTag"],"v5.5.0-windows.1")
        self.assertEqual(out["capabilitiesSource"]["commit"],"a"*40)

    def test_denies_missing_report(self):
        self.assets.pop("pg_partman-v5.5.0-pg14-windows-x64.vulnerabilities.json")
        with self.assertRaises(mod.UnsafeCatalog):self.record()

    def test_denies_unexpected_upstream(self):
        self.manifest["upstream"]["repository"]="attacker/other"
        with self.assertRaises(mod.UnsafeCatalog):self.record()

    def test_denies_partial_postgresql_matrix(self):
        with self.assertRaises(mod.UnsafeCatalog):
            mod.update_record(self.old,self.rel,self.manifest,self.contract,
                              self.assets,self.sums,"a"*40,required_majors=[15,16,17,18])

    def test_denies_unsigned_origin(self):
        self.assertFalse(mod.valid_build_origin({"workflowRun":{
            "ref":"refs/heads/main","event":"workflow_dispatch"},"buildMode":"normal"},"v5.5.0-windows.1"))
        self.assertTrue(mod.valid_build_origin({"workflowRun":{
            "ref":"refs/heads/release/v5.5.0-windows.1","event":"push"},
            "buildMode":"release-attested"},"v5.5.0-windows.1"))

if __name__=="__main__":unittest.main()
