#!/usr/bin/env python3
"""Offline Catalog v2 release-to-record mapping and fail-closed tests."""
import importlib.util
import copy
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[1]/"scripts"/"propose_verified_release.py"
spec=importlib.util.spec_from_file_location("verified_release",path)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class CatalogProposal(unittest.TestCase):
    def setUp(self):
        self.old={
            "schemaVersion":2,"name":"plpgsql_check","repository":"pgextwin/plpgsql_check",
            "upstream":{"version":"2.10.13"},"latest":{},
            "postgresql":{str(m):{} for m in [15,16,17,18]},
            "runtime":{"requirements":{}}, "capabilities":{}, "capabilitiesSource":{}
        }
        self.tag="v2.10.14-windows.1"
        self.release={"tag_name":self.tag,"published_at":"2026-10-09T12:00:00Z",
                      "draft":False,"prerelease":False}
        self.manifest={"name":"plpgsql_check",
                       "upstream":{"repository":"okbob/plpgsql_check","version":"2.10.14"},
                       "postgresql":{"majors":[15,16,17,18]}}
        self.contract={"contractVersion":2,"extension":"plpgsql_check",
                       "runtimeRequirements":{"preload":"optional"},"coverage":{"upgrade":"not-covered"},
                       "functionalScenarios":[{"id":"test","description":"test","evidence":["sql-result"]}]}
        self.assets={"SHA256SUMS.txt":{"name":"SHA256SUMS.txt","state":"uploaded"}}
        for m in [15,16,17,18]:
            stem="plpgsql_check-v2.10.14-pg"+str(m)+"-windows-x64"
            for suf in (".zip",".spdx.json",".vulnerabilities.json"):
                n=stem+suf;self.assets[n]={"name":n,"state":"uploaded"}
        self.sums={k:"f"*64 for k in self.assets if k!="SHA256SUMS.txt"}

    def convert(self):
        return mod.update_record(self.old,self.release,self.manifest,self.contract,
                                 self.assets,self.sums,"a"*40)

    def test_maps_all_assets_and_preserves_history(self):
        out=self.convert()
        self.assertEqual(out["latest"]["releaseTag"],self.tag)
        self.assertEqual(out["capabilitiesSource"]["commit"],"a"*40)
        self.assertEqual(out["runtime"]["requirements"],self.contract["runtimeRequirements"])
        self.assertEqual(len(out["postgresql"]),4)
        self.assertIn("pg17",out["postgresql"]["17"]["asset"])
        self.assertEqual(self.old["upstream"]["version"],"2.10.13")

    def test_fails_closed_on_draft(self):
        self.release["draft"]=True
        with self.assertRaises(mod.UnsafeCatalog):self.convert()

    def test_fails_on_asset_missing(self):
        del self.assets[next(k for k in self.assets if k.endswith(".zip"))]
        with self.assertRaises(mod.UnsafeCatalog):self.convert()

    def test_fails_on_checksum_missing(self):
        del self.sums[next(iter(self.sums))]
        with self.assertRaises(mod.UnsafeCatalog):self.convert()

    def test_fails_on_pg_major_incomplete(self):
        self.manifest["postgresql"]["majors"]=[15,16,17]
        with self.assertRaises(mod.UnsafeCatalog):self.convert()

    def test_fails_on_tag_version_mismatch(self):
        self.manifest["upstream"]["version"]="2.10.99"
        with self.assertRaises(mod.UnsafeCatalog):self.convert()

if __name__=="__main__":unittest.main()
