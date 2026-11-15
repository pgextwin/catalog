"""Offline fail-closed selector checks for OSGeo Windows SQL acceptance."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from issue112_osgeo_pg14_17_windows_selection import make_selection
from test_issue112_osgeo_pg14_17_static_review import latest_snapshot, snapshot

class OriginalSelectionTests(unittest.TestCase):
    def test_all_exact_major_pins_remain_unpublished(self):
        expected_urls = {
            "14": "https://download-cache.osgeo.org/postgis/windows/pg14/postgis-bundle-pg14-3.6.1x64.zip",
            "15": "https://download-cache.osgeo.org/postgis/windows/pg15/postgis-bundle-pg15-3.6.2x64.zip",
            "16": "https://download-cache.osgeo.org/postgis/windows/pg16/archive/postgis-bundle-pg16-3.6.2x64.zip",
            "17": "https://download-cache.osgeo.org/postgis/windows/pg17/archive/postgis-bundle-pg17-3.6.2x64.zip",
        }
        for snap in (snapshot(), latest_snapshot()):
            for pg in ("14", "15", "16", "17"):
                row = make_selection(snap, pg)
                self.assertEqual(row["pgMajor"], pg)
                self.assertEqual(row["sourceUrl"], expected_urls[pg])
                self.assertEqual(len(row["expectedSha256"]), 64)
                for permission in ("windowsSqlRuntimeVerified", "dynamicDependenciesVerified",
                                   "allComponentNoticesVerified", "producerProvenanceVerified",
                                   "independentSignatureVerified", "publicGetAuthorized",
                                   "mirrorAuthorized", "publisherAuthorized", "releaseAuthorized"):
                    self.assertIs(row[permission], False, permission)
            with self.assertRaises(ValueError):
                make_selection(snap, "18")

    def test_original_metadata_identity_is_mandatory(self):
        for corruption in ("wrong-version", "authorize", "wrong-host", "missing-major"):
            candidate = copy.deepcopy(snapshot())
            if corruption == "wrong-version":
                candidate["latestBundleSelection"]["selected"][0]["version"] = "9.9.9"
            elif corruption == "authorize":
                candidate["latestBundleSelection"]["downloadAuthorized"] = True
            elif corruption == "wrong-host":
                candidate["sourceIndex"] = "https://attacker.example/postgis/windows/"
            else:
                candidate["latestBundleSelection"]["selected"].pop(0)
            with self.assertRaises(ValueError, msg=corruption):
                make_selection(candidate, "14")

        for corruption in ("authorize", "wrong-host", "empty-selected"):
            candidate = copy.deepcopy(latest_snapshot())
            if corruption == "authorize":
                candidate["latestBundleSelection"]["downloadAuthorized"] = True
            elif corruption == "wrong-host":
                candidate["sourceIndex"] = "https://attacker.example/postgis/windows/"
            else:
                candidate["latestBundleSelection"]["selected"].clear()
            with self.assertRaises(ValueError, msg=corruption):
                make_selection(candidate, "14")

if __name__ == "__main__":
    unittest.main()
