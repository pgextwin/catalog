"""Offline fail-closed selector checks for OSGeo Windows SQL acceptance."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue112_osgeo_pg14_17_windows_selection import make_selection
from test_issue112_osgeo_pg14_17_static_review import snapshot

class OriginalSelectionTests(unittest.TestCase):
    def test_all_exact_major_pins_remain_unpublished(self):
        for pg in ("14", "15", "16", "17"):
            row = make_selection(snapshot(), pg)
            self.assertEqual(row["pgMajor"], pg)
            self.assertEqual(len(row["expectedSha256"]), 64)
            for permission in ("windowsSqlRuntimeVerified", "dynamicDependenciesVerified",
                               "allComponentNoticesVerified", "producerProvenanceVerified",
                               "independentSignatureVerified", "publicGetAuthorized",
                               "mirrorAuthorized", "publisherAuthorized", "releaseAuthorized"):
                self.assertIs(row[permission], False, permission)
        with self.assertRaises(ValueError):
            make_selection(snapshot(), "18")

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

if __name__ == "__main__":
    unittest.main()
