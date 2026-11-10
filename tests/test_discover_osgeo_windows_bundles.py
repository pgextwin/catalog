"""Offline hostile tests for OSGeo Windows bundle HTML index discovery."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import discover_osgeo_windows_bundles as s  # noqa: E402


ROOT_HTML = """
<html><body>
<a href="../">Parent Directory</a>
<a href="pg14/">pg14/</a><a href="pg18/">pg18/</a>
<a href="source/">source/</a><a href="?C=N;O=D">sort</a>
</body></html>
"""
PG14 = """
<a href="../">Parent</a><a href="archive/">archive/</a>
<a href="postgis-bundle-pg14-3.6.1x64.zip">zip</a>
<a href="postgis-bundle-pg14-3.6.1x64.zip.md5">md5</a>
"""
PG14_ARCHIVE = """
<a href="../">Parent</a>
<a href="postgis-bundle-pg14x64-setup-3.5.2-1.exe">installer</a>
"""
PG18 = """
<a href="../">Parent</a><a href="archive/">archive</a>
<a href="postgis-bundle-pg18-3.6.2x64.zip">binary</a>
<a href="postgis-bundle-pg18-3.6.2x64.zip.md5">md5</a>
"""
PG18_ARCHIVE = """
<a href="../">Parent</a>
<a href="postgis-bundle-pg18-3.6.1x64.zip">old</a>
"""
PAGES = {
    "": ROOT_HTML, "pg14/": PG14, "pg14/archive/": PG14_ARCHIVE,
    "pg18/": PG18, "pg18/archive/": PG18_ARCHIVE,
}


def fake_fetch(directory):
    return s.parse_listing(PAGES[directory])


class OsgeoDiscoveryTests(unittest.TestCase):
    def test_exact_bounded_folder_history_and_no_authorization(self):
        report = s.scan("osu-mirror", fake_fetch)
        self.assertEqual(2, report["majorDirectories"])
        self.assertEqual(2, report["archiveDirectories"])
        self.assertEqual(5, report["scannedIndexDirectories"])
        self.assertEqual(4, report["bundleFiles"])
        self.assertEqual(["14", "18"], report["pgMajors"])
        self.assertEqual("UNTRUSTED_DIRECTORY_METADATA_ONLY", report["sourceKind"])
        self.assertFalse(report["publicationAuthorized"])
        self.assertFalse(report["redistributionAuthorized"])
        records = report["candidates"]
        self.assertTrue(all(not r["downloadAuthorized"] and
                            not r["mirrorAuthorized"] and
                            not r["bundleContentsVerified"] and
                            not r["originalSha256Verified"] and
                            not r["provenanceVerified"] and
                            not r["dependenciesAndAbiVerified"] for r in records))
        self.assertEqual({"3.6.1", "3.5.2", "3.6.2"}, {
            r["packagedPostgisVersion"] for r in records})
        self.assertTrue(any(r["md5SidecarPresent"] for r in records))
        self.assertTrue(any(r["historicalDirectory"] for r in records))
        self.assertTrue(any(r["artifactKind"] == "bundle-installer-exe" for r in records))
        self.assertFalse(any("downloadUrl" in r for r in records))

    def test_pg80_is_8_0_and_archive_is_not_new_version(self):
        self.assertEqual("8.0", s.normalize_major("pg80/"))
        self.assertEqual("9.6", s.normalize_major("pg96/"))
        self.assertEqual("18", s.normalize_major("pg18/"))
        self.assertEqual("19", s.normalize_major("pg19/"))

    def test_malicious_links_are_never_traversed(self):
        links = s.parse_listing("""
          <a href="../">parent</a>
          <a href="pg18/">yes</a>
          <a href="//evil.tld/outside/">bad</a>
          <a href="https://evil.tld/x.zip">bad</a>
          <a href="../evil.zip">bad</a>
          <a href="%2e%2e%2fevil.zip">bad</a>
          <a href="a.zip?token=secret">bad</a>
          <a href="postgis-bundle-pg18-3.6.2x64.zip">yes</a>
        """)
        self.assertEqual(["pg18/", "postgis-bundle-pg18-3.6.2x64.zip"], links)

    def test_reject_duplicate_and_oversized_index(self):
        with self.assertRaises(ValueError):
            s.parse_listing('<a href="pg18/">one</a><a href="pg18/">two</a>')
        with self.assertRaises(ValueError):
            s.parse_listing(b"a" * (s.MAX_LISTING_BYTES + 1))

    def test_disallow_wrong_origin_path(self):
        for directory in ("https://example.org/", "../", "pg18/../../",
                          "pg18/archive/evil/", "pg18/%2e%2e/"):
            with self.assertRaises(ValueError):
                s.fetch_index("osu-mirror", directory)
        with self.assertRaises(ValueError):
            s.scan("unknown", fake_fetch)

    def test_wrong_pg_bundle_and_missing_indexes_fail_closed(self):
        pages = copy.deepcopy(PAGES)
        pages["pg18/"] = '<a href="postgis-bundle-pg17-3.6.2x64.zip">bad</a>'
        with self.assertRaises(ValueError):
            s.scan("osu-mirror", lambda d: s.parse_listing(pages[d]))
        with self.assertRaises(ValueError):
            s.scan("osu-mirror", lambda d: [] if d == "pg18/archive/" else fake_fetch(d))

    def test_current_latest_bundles_support_per_major_or_one_bundle(self):
        report = s.scan("osu-mirror", fake_fetch)
        per_pg = s.select_latest_bundles(report)
        self.assertEqual(per_pg["mode"], "latest-per-supported-pg")
        self.assertFalse(per_pg["downloadAuthorized"])
        self.assertFalse(per_pg["mirrorAuthorized"])
        self.assertEqual([(x["pgMajor"], x["version"]) for x in per_pg["selected"]],
                         [("14", "3.6.1"), ("18", "3.6.2")])
        self.assertTrue(all(not x["downloadAuthorized"] and
                            not x["mirrorAuthorized"] for x in per_pg["selected"]))
        single = s.select_latest_bundles(report, single_bundle=True)
        self.assertEqual(single["mode"], "single-newest-bundle")
        self.assertEqual(len(single["selected"]), 1)
        self.assertEqual(single["selected"][0]["pgMajor"], "18")
        self.assertEqual(single["selected"][0]["version"], "3.6.2")

    def test_bundled_latest_prefers_semver_over_pg_major_and_ignores_archive(self):
        report = s.scan("osu-mirror", fake_fetch)
        current = copy.deepcopy(next(c for c in report["candidates"]
                                     if c["pgMajor"] == "14" and
                                     not c["historicalDirectory"]))
        current["fileName"] = "postgis-bundle-pg14-3.7.0x64.zip"
        current["sourceRelativePath"] = "pg14/" + current["fileName"]
        current["packagedPostgisVersion"] = "3.7.0"
        report["candidates"].append(current)
        single = s.select_latest_bundles(report, single_bundle=True)
        self.assertEqual(single["selected"][0]["fileName"],
                         "postgis-bundle-pg14-3.7.0x64.zip")
        self.assertEqual(single["selected"][0]["pgMajor"], "14")

    def test_latest_selection_rejects_attempted_authority_escalation(self):
        original = s.scan("osu-mirror", fake_fetch)
        for field in ("downloadAuthorized", "mirrorAuthorized",
                      "bundleContentsVerified", "originalSha256Verified",
                      "licensesAndNoticesVerified", "dependenciesAndAbiVerified",
                      "provenanceVerified"):
            with self.subTest(field=field):
                bad = copy.deepcopy(original)
                record = next(x for x in bad["candidates"]
                              if x["artifactKind"] == "bundle-zip" and
                              not x["historicalDirectory"])
                record[field] = True
                with self.assertRaises(ValueError):
                    s.select_latest_bundles(bad)
        bad = copy.deepcopy(original)
        bad["publicationAuthorized"] = True
        with self.assertRaises(ValueError):
            s.select_latest_bundles(bad)
        bad = copy.deepcopy(original)
        bad["candidates"] = []
        with self.assertRaises(ValueError):
            s.select_latest_bundles(bad)

    def test_no_binary_transport_or_publication_code(self):
        source = (ROOT / "scripts/discover_osgeo_windows_bundles.py").read_text()
        self.assertNotIn("releases/upload", source)
        self.assertNotIn("workflow_dispatch", source)
        self.assertNotIn("Authorization:", source)
        self.assertNotIn("POST", source)
        self.assertNotIn("DELETE", source)
        self.assertFalse(s.BINARY_NAME.fullmatch("pg18/postgis-bundle.zip"))


if __name__ == "__main__":
    unittest.main()
