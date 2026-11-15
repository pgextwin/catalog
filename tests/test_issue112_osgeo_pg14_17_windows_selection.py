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

        for corruption in ("authorize", "wrong-host", "empty-selected", "wrong-path-archive"):
            candidate = copy.deepcopy(latest_snapshot())
            if corruption == "authorize":
                candidate["latestBundleSelection"]["downloadAuthorized"] = True
            elif corruption == "wrong-host":
                candidate["sourceIndex"] = "https://attacker.example/postgis/windows/"
            elif corruption == "wrong-path-archive":
                candidate["latestBundleSelection"]["selected"][1]["sourceRelativePath"] = (
                    "pg16/archive/postgis-bundle-pg16-3.7.0x64.zip"
                )
            else:
                candidate["latestBundleSelection"]["selected"].clear()
            with self.assertRaises(ValueError, msg=corruption):
                make_selection(candidate, "14")

        for pg, bad_path in (
            ("14", "pg14/archive/postgis-bundle-pg14-3.6.1x64.zip"),
            ("15", "pg15/archive/postgis-bundle-pg15-3.6.2x64.zip"),
            ("16", "pg16/other/postgis-bundle-pg16-3.6.2x64.zip"),
            ("17", "pg17/../pg17/postgis-bundle-pg17-3.6.2x64.zip"),
        ):
            candidate = copy.deepcopy(snapshot())
            idx = int(pg) - 14
            candidate["latestBundleSelection"]["selected"][idx]["sourceRelativePath"] = bad_path
            with self.assertRaises(ValueError, msg=f"bad-path-{pg}"):
                make_selection(candidate, pg)

    def test_windows_runtime_ps1_uses_explicit_fixed_url_allowlist_and_no_redirects(self):
        ps1 = (Path(__file__).resolve().parents[1] /
               "scripts/issue112-osgeo-pg14-17-windows-runtime.ps1").read_text(encoding="utf-8")
        expected_pins = {
            "14": ("3.6.1", "pg14/", 124000548, "d95f1e0ed333c3b0729210fb6573d4d7e07bc7eba61868d51fb1eebd338b1a97"),
            "15": ("3.6.2", "pg15/", 123986945, "520c3fd7ebf95050d8d89dc1b626f4f43111a3d726f60b73bbbbbd95784688eb"),
            "16": ("3.6.2", "pg16/archive/", 123957610, "9f4e8a30d69ed7cc0088dd3d218ac65bd4e26aa5b7bffcb2ebd7dcb74a4ff2a6"),
            "17": ("3.6.2", "pg17/archive/", 123959035, "7ba180ee2a352987b9a2f194673652c59483b55852295ccf401dceccd8765425"),
        }
        for pg, (ver, subdir, size, sha) in expected_pins.items():
            url = f"https://download-cache.osgeo.org/postgis/windows/{subdir}postgis-bundle-pg{pg}-{ver}x64.zip"
            self.assertIn(url, ps1)
            self.assertIn(str(size), ps1)
            self.assertIn(sha, ps1)
        self.assertNotIn("pg$Major/", ps1)
        self.assertNotIn("pg14/archive/", ps1)
        self.assertNotIn("pg15/archive/", ps1)
        self.assertIn("-MaximumRedirection 0", ps1)
        self.assertNotIn("-MaximumRedirection 3", ps1)
        for guard in (
            "CANDIDATE_ONLY",
            "OSGEO_ORIGINAL_BYTES=PASS",
            "OSGEO_WINDOWS_LAYOUT=PASS",
            "OSGEO_WINDOWS_REAL_SQL=PASS",
            "Original OSGeo byte identity mismatch",
            "Unexpected OSGeo original identity or URL",
        ):
            self.assertIn(guard, ps1)

if __name__ == "__main__":
    unittest.main()
