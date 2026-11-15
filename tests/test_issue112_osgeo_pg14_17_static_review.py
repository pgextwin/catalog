"""Adversarial offline tests of OSGeo PG14-17 nonpublishing review."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import discover_osgeo_windows_bundles as d
import issue112_osgeo_pg14_17_static_review as p

def snapshot():
    rows = []
    for pg in ("14", "15", "16", "17"):
        version = p.PINS[pg][0]
        name = f"postgis-bundle-pg{pg}-{version}x64.zip"
        rows.append(dict(pgMajor=pg, version=version, fileName=name,
                         sourceRelativePath=f"pg{pg}/{name}",
                         downloadAuthorized=False, mirrorAuthorized=False))
    return dict(schemaVersion="pgextwin-osgeo-postgis-windows-directory-snapshot/v1",
                sourceKind="UNTRUSTED_DIRECTORY_METADATA_ONLY",
                sourceIndex=p.ORIGIN,
                publicationAuthorized=False, redistributionAuthorized=False,
                latestBundleSelection=dict(scope="UNVERIFIED_METADATA_SELECTION_ONLY",
                    mode="pinned-per-pg-originals", downloadAuthorized=False,
                    mirrorAuthorized=False, selected=rows))


def latest_snapshot(versions=None):
    versions = versions or {"15": "3.6.2", "16": "3.7.0", "17": "3.7.0", "18": "3.7.0"}
    rows = []
    for pg, version in versions.items():
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

EXPECTED_DIRS = {
    "14": "pg14/",
    "15": "pg15/",
    "16": "pg16/archive/",
    "17": "pg17/archive/",
}


class DenyTests(unittest.TestCase):
    def test_exact_four_pins_and_no_pg18(self):
        for pg in p.PINS:
            got = p.select(snapshot(), pg)
            self.assertEqual(len(got["expectedSha256"]), 64)
            self.assertEqual(
                got["sourceUrl"],
                f"{p.ORIGIN}{EXPECTED_DIRS[pg]}postgis-bundle-pg{pg}-{p.PINS[pg][0]}x64.zip",
            )
        with self.assertRaises(ValueError):
            p.select(snapshot(), "18")

    def test_accepts_realistic_discover_latest_snapshot_and_derives_pins(self):
        for snap in (latest_snapshot(), latest_snapshot({"15": "3.6.2", "18": "3.7.0"})):
            for pg, (version, size, sha) in p.PINS.items():
                with self.subTest(pg=pg, selected=len(snap["latestBundleSelection"]["selected"])):
                    got = p.select(snap, pg)
                    self.assertEqual(got["pgMajor"], pg)
                    self.assertEqual(got["version"], version)
                    self.assertEqual(got["expectedBytes"], size)
                    self.assertEqual(got["expectedSha256"], sha)
                    self.assertEqual(
                        got["sourceUrl"],
                        f"{p.ORIGIN}{EXPECTED_DIRS[pg]}postgis-bundle-pg{pg}-{version}x64.zip",
                    )
        with self.assertRaises(ValueError):
            p.select(latest_snapshot(), "18")

        pages = {
            "": '<a href="pg14/">pg14/</a><a href="pg15/">pg15/</a><a href="pg16/">pg16/</a><a href="pg17/">pg17/</a><a href="pg18/">pg18/</a>',
            "pg14/": '<a href="postgis-bundle-pg14-3.6.1x64.zip">z</a>',
            "pg15/": '<a href="postgis-bundle-pg15-3.6.2x64.zip">z</a>',
            "pg16/": '<a href="postgis-bundle-pg16-3.7.0x64.zip">z</a>',
            "pg17/": '<a href="postgis-bundle-pg17-3.7.0x64.zip">z</a>',
            "pg18/": '<a href="postgis-bundle-pg18-3.7.0x64.zip">z</a>',
        }
        discovered = d.scan("osgeo-cache", lambda dir_path: d.parse_listing(pages[dir_path]))
        discovered["latestBundleSelection"] = d.select_latest_bundles(discovered)
        for pg in p.PINS:
            got = p.select(discovered, pg)
            self.assertEqual(got["expectedSha256"], p.PINS[pg][2])
            self.assertEqual(
                got["sourceUrl"],
                f"{p.ORIGIN}{EXPECTED_DIRS[pg]}postgis-bundle-pg{pg}-{p.PINS[pg][0]}x64.zip",
            )
        with self.assertRaises(ValueError):
            p.select(discovered, "18")

    def test_reject_forged_or_changed_metadata(self):
        for mutate in (
            lambda x: x["latestBundleSelection"].update(downloadAuthorized=True),
            lambda x: x["latestBundleSelection"].update(mode="latest-per-supported-pg"),
            lambda x: x["latestBundleSelection"].update(mode="single-newest-bundle"),
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

        for label, mutate in (
            ("wrong_schema", lambda x: x.update(schemaVersion="wrong/v1")),
            ("wrong_source_kind", lambda x: x.update(sourceKind="TRUSTED")),
            ("wrong_index_mirror", lambda x: x.update(
                sourceIndex="https://ftp2.osuosl.org/pub/osgeo/download/postgis/windows/")),
            ("wrong_index_evil", lambda x: x.update(
                sourceIndex="https://evil.example/postgis/windows/")),
            ("pub_auth", lambda x: x.update(publicationAuthorized=True)),
            ("redist_auth", lambda x: x.update(redistributionAuthorized=True)),
            ("sel_download_auth", lambda x: x["latestBundleSelection"].update(downloadAuthorized=True)),
            ("sel_mirror_auth", lambda x: x["latestBundleSelection"].update(mirrorAuthorized=True)),
            ("wrong_scope", lambda x: x["latestBundleSelection"].update(scope="TRUSTED")),
            ("wrong_mode", lambda x: x["latestBundleSelection"].update(mode="single-newest-bundle")),
            ("empty_selected", lambda x: x["latestBundleSelection"]["selected"].clear()),
            ("row_download_auth", lambda x: x["latestBundleSelection"]["selected"][-1].update(
                downloadAuthorized=True)),
            ("forged_path", lambda x: x["latestBundleSelection"]["selected"][0].update(
                sourceRelativePath="pg15/../evil.zip")),
            ("archive_path_in_latest", lambda x: x["latestBundleSelection"]["selected"][1].update(
                sourceRelativePath="pg16/archive/postgis-bundle-pg16-3.7.0x64.zip")),
            ("eol_pg14_in_latest", lambda x: x["latestBundleSelection"]["selected"].append(
                dict(pgMajor="14", version="3.6.1",
                     fileName="postgis-bundle-pg14-3.6.1x64.zip",
                     sourceRelativePath="pg14/postgis-bundle-pg14-3.6.1x64.zip",
                     downloadAuthorized=False, mirrorAuthorized=False))),
        ):
            with self.subTest(mutation=label):
                candidate = copy.deepcopy(latest_snapshot())
                mutate(candidate)
                with self.assertRaises(ValueError):
                    p.select(candidate, "14")

        for pg, bad_ver in (("14", "3.6.2"), ("15", "3.7.0"), ("16", "3.7.0"), ("17", "3.7.0")):
            candidate = copy.deepcopy(snapshot())
            idx = int(pg) - 14
            bad_name = f"postgis-bundle-pg{pg}-{bad_ver}x64.zip"
            candidate["latestBundleSelection"]["selected"][idx].update(
                version=bad_ver, fileName=bad_name, sourceRelativePath=f"pg{pg}/{bad_name}"
            )
            with self.assertRaises(ValueError, msg=f"pinned-wrong-version-{pg}"):
                p.select(candidate, pg)

        with self.assertRaises(ValueError):
            p.read_original(
                "https://evil.example/postgis/windows/pg16/archive/postgis-bundle-pg16-3.6.2x64.zip",
                Path("/tmp/unused.zip"),
            )

    def test_digest_mismatch_stops_before_archive(self):
        for pg in ("14", "16", "17"):
            _, size, sha = p.PINS[pg]
            for bad in ((1, "f" * 64), (size, "0" * 64), (size - 1, sha)):
                with self.subTest(pg=pg, bad=bad), \
                     patch.object(p, "read_original", return_value=bad), \
                     patch.object(p, "inspect") as check:
                    with self.assertRaises(ValueError):
                        p.run(snapshot(), pg)
                    check.assert_not_called()

    def test_all_public_permissions_remain_denied(self):
        pin = p.select(snapshot(), "16")
        self.assertEqual(
            pin["sourceUrl"],
            f"{p.ORIGIN}pg16/archive/postgis-bundle-pg16-3.6.2x64.zip",
        )
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
