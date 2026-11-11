"""Adversarial offline tests of OSGeo PG14-17 nonpublishing review."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_osgeo_pg14_17_static_review as p

def snapshot():
    rows = []
    for pg in ("14", "15", "16", "17", "18"):
        version = p.PINS[pg][0] if pg in p.PINS else "3.7.0"
        name = f"postgis-bundle-pg{pg}-{version}x64.zip"
        rows.append(dict(pgMajor=pg, version=version, fileName=name,
                         sourceRelativePath=f"pg{pg}/{name}",
                         downloadAuthorized=False, mirrorAuthorized=False))
    return dict(schemaVersion="pgextwin-osgeo-postgis-windows-directory-snapshot/v1",
                sourceKind="UNTRUSTED_DIRECTORY_METADATA_ONLY",
                sourceIndex=p.ORIGIN,
                publicationAuthorized=False, redistributionAuthorized=False,
                latestBundleSelection=dict(scope="UNVERIFIED_METADATA_SELECTION_ONLY",
                    mode="latest-per-supported-pg", downloadAuthorized=False,
                    mirrorAuthorized=False, selected=rows))

class DenyTests(unittest.TestCase):
    def test_exact_four_pins_and_no_pg18(self):
        for pg in p.PINS:
            self.assertEqual(len(p.select(snapshot(), pg)["expectedSha256"]), 64)
        with self.assertRaises(ValueError):
            p.select(snapshot(), "18")

    def test_reject_forged_or_changed_metadata(self):
        for mutate in (
            lambda x: x["latestBundleSelection"].update(downloadAuthorized=True),
            lambda x: x.update(sourceIndex="https://ftp2.osuosl.org/pub/osgeo/download/postgis/windows/"),
            lambda x: x["latestBundleSelection"]["selected"].pop(),
            lambda x: x["latestBundleSelection"]["selected"][0].update(
                version="3.9.9", fileName="postgis-bundle-pg14-3.9.9x64.zip",
                sourceRelativePath="pg14/postgis-bundle-pg14-3.9.9x64.zip"),
        ):
            candidate = copy.deepcopy(snapshot())
            mutate(candidate)
            with self.assertRaises(ValueError):
                p.select(candidate, "14")

    def test_digest_mismatch_stops_before_archive(self):
        with patch.object(p, "read_original", return_value=(1, "f" * 64)), \
             patch.object(p, "inspect") as check:
            with self.assertRaises(ValueError):
                p.run(snapshot(), "14")
            check.assert_not_called()

    def test_all_public_permissions_remain_denied(self):
        pin = p.select(snapshot(), "16")
        graph = {"dllCount": 1, "parsedPeCount": 0, "nonParsed": [],
                 "unbundledImportTriage": [], "coreServerImportPaths": {},
                 "dllImports": []}
        with patch.object(p, "read_original",
                          return_value=(pin["expectedBytes"], pin["expectedSha256"])), \
             patch.object(p, "inspect", return_value={"zipMembers": 8}), \
             patch.object(p, "member_receipts",
                          return_value=([{"path": "a.dll"}], [])), \
             patch.object(p, "dependency_inventory", return_value=graph):
            receipt = p.run(snapshot(), "16")
        for key in ("allComponentNoticesVerified", "dynamicDependenciesVerified",
                    "windowsSqlRuntimeVerified", "producerProvenanceVerified",
                    "independentSignatureVerified", "publicGetAuthorized",
                    "mirrorAuthorized", "releaseAuthorized", "publisherAuthorized"):
            self.assertIs(receipt[key], False, key)

if __name__ == "__main__":
    unittest.main()
