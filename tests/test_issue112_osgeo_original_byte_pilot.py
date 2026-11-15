"""Offline hostile boundary tests; never reach an external network."""
import copy
import io
import hashlib
from unittest import mock
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import discover_osgeo_windows_bundles as d
import issue112_osgeo_original_byte_pilot as p


def snapshot():
    row = {"fileName": "postgis-bundle-pg18-3.7.0x64.zip", "pgMajor": "18",
           "version": "3.7.0", "sourceRelativePath": "pg18/postgis-bundle-pg18-3.7.0x64.zip",
           "downloadAuthorized": False, "mirrorAuthorized": False}
    return {"schemaVersion": "pgextwin-osgeo-postgis-windows-directory-snapshot/v1",
            "sourceKind": "UNTRUSTED_DIRECTORY_METADATA_ONLY",
            "sourceIndex": "https://download-cache.osgeo.org/postgis/windows/",
            "publicationAuthorized": False, "redistributionAuthorized": False,
            "latestBundleSelection": {"scope": "UNVERIFIED_METADATA_SELECTION_ONLY",
                                      "mode": "single-newest-bundle", "downloadAuthorized": False,
                                      "mirrorAuthorized": False, "selected": [row]}}



def latest_snapshot(versions=None):
    report = snapshot()
    versions = versions or {"15": "3.6.2", "16": "3.7.0", "17": "3.7.0", "18": "3.7.0"}
    selected = []
    for pg, version in versions.items():
        filename = f"postgis-bundle-pg{pg}-{version}x64.zip"
        selected.append({"fileName": filename, "pgMajor": pg,
                         "version": version,
                         "sourceRelativePath": f"pg{pg}/{filename}",
                         "downloadAuthorized": False, "mirrorAuthorized": False})
    report["latestBundleSelection"]["mode"] = "latest-per-supported-pg"
    report["latestBundleSelection"]["selected"] = selected
    return report


def pinned_snapshot():
    report = snapshot()
    selected = []
    for pg in ("14", "15", "16", "17"):
        filename = f"postgis-bundle-pg{pg}-3.6.2x64.zip"
        selected.append({"fileName": filename, "pgMajor": pg,
                         "version": "3.6.2",
                         "sourceRelativePath": f"pg{pg}/{filename}",
                         "downloadAuthorized": False, "mirrorAuthorized": False})
    report["latestBundleSelection"]["mode"] = "pinned-per-pg-originals"
    report["latestBundleSelection"]["selected"] = selected
    return report


def pe():
    raw = bytearray(128)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3c, 80)
    raw[80:86] = b"PE\0\0\x64\x86"
    return bytes(raw)


def fixture(members):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, content in members.items():
            z.writestr(name, content)
    return b.getvalue()


class OriginalBytePilotTests(unittest.TestCase):
    def test_latest_bundle_safe_identity_and_get_deny(self):
        url, row = p.choose(snapshot())
        self.assertEqual(url, "https://download-cache.osgeo.org/postgis/windows/pg18/postgis-bundle-pg18-3.7.0x64.zip")
        self.assertFalse(row["downloadAuthorized"])

    def test_denies_fake_trust_major_version_and_path(self):
        for field, value in [("pgMajor", "19"), ("version", "3.6.0"),
                             ("downloadAuthorized", True), ("mirrorAuthorized", True),
                             ("sourceRelativePath", "pg18/../evil.zip")]:
            with self.subTest(field=field):
                bad = copy.deepcopy(snapshot())
                bad["latestBundleSelection"]["selected"][0][field] = value
                with self.assertRaises(ValueError):
                    p.choose(bad)
        bad = snapshot()
        bad["latestBundleSelection"]["mode"] = "latest-per-supported-pg"
        with self.assertRaises(ValueError):
            p.choose(bad)
        bad = snapshot()
        bad["publicationAuthorized"] = True
        with self.assertRaises(ValueError):
            p.choose(bad)


    def test_pg14_to_17_independent_original_selectors(self):
        report = latest_snapshot()
        expected = {"15": "3.6.2", "16": "3.7.0", "17": "3.7.0"}
        for pg, version in expected.items():
            with self.subTest(pg=pg):
                url, row = p.choose_major(report, pg)
                self.assertEqual(url, (
                    f"https://download-cache.osgeo.org/postgis/windows/pg{pg}/"
                    f"postgis-bundle-pg{pg}-{version}x64.zip"))
                self.assertFalse(row["downloadAuthorized"])
                self.assertFalse(row["mirrorAuthorized"])
        with self.assertRaisesRegex(ValueError, "OSGeo original-byte pilot DENY"):
            p.choose_major(report, "14")
        with self.assertRaises(ValueError):
            p.choose_major(report, "18")

        partial = latest_snapshot({"15": "3.6.2", "18": "3.7.0"})
        url, row = p.choose_major(partial, "15")
        self.assertEqual(row["version"], "3.6.2")
        self.assertIn("/pg15/", url)
        for absent in ("14", "16", "17"):
            with self.subTest(absent=absent), self.assertRaisesRegex(
                    ValueError, "OSGeo original-byte pilot DENY"):
                p.choose_major(partial, absent)

    def test_per_major_selector_denies_incomplete_duplicates_and_escalation(self):
        base = latest_snapshot()
        pg14_row = {"fileName": "postgis-bundle-pg14-3.6.1x64.zip", "pgMajor": "14",
                    "version": "3.6.1",
                    "sourceRelativePath": "pg14/postgis-bundle-pg14-3.6.1x64.zip",
                    "downloadAuthorized": False, "mirrorAuthorized": False}
        mutations = [
            ("empty_selected", lambda r: r["latestBundleSelection"]["selected"].clear()),
            ("eol_pg14_in_latest", lambda r: r["latestBundleSelection"]["selected"].append(pg14_row)),
            ("duplicate_major", lambda r: r["latestBundleSelection"]["selected"][1].update(
                {"pgMajor": "15", "fileName": "postgis-bundle-pg15-3.6.2x64.zip",
                 "version": "3.6.2",
                 "sourceRelativePath": "pg15/postgis-bundle-pg15-3.6.2x64.zip"})),
            ("row_download_auth", lambda r: r["latestBundleSelection"]["selected"][0].update(
                {"downloadAuthorized": True})),
            ("unselected_pg18_download_auth", lambda r: r["latestBundleSelection"]["selected"][-1].update(
                {"downloadAuthorized": True})),
            ("forged_path", lambda r: r["latestBundleSelection"]["selected"][2].update(
                {"sourceRelativePath": "pg17/../forged.zip"})),
            ("wrong_mode", lambda r: r["latestBundleSelection"].update(
                {"mode": "single-newest-bundle"})),
            ("wrong_source_kind", lambda r: r.update(
                {"sourceKind": "TRUSTED_DIRECTORY"})),
            ("wrong_source_index", lambda r: r.update(
                {"sourceIndex": "https://evil.example/postgis/windows/"})),
            ("publication_auth", lambda r: r.update({"publicationAuthorized": True})),
        ]
        for label, mutation in mutations:
            with self.subTest(mutation=label):
                report = copy.deepcopy(base)
                mutation(report)
                with self.assertRaises(ValueError):
                    p.choose_major(report, "15")

    def test_choose_fixed_major_pg14_to_17_and_denies_pg18_and_mutations(self):
        report = pinned_snapshot()
        for pg in ("14", "15", "16", "17"):
            with self.subTest(pg=pg):
                url, row = p.choose_fixed_major(report, pg)
                self.assertEqual(url, (
                    f"https://download-cache.osgeo.org/postgis/windows/pg{pg}/"
                    f"postgis-bundle-pg{pg}-3.6.2x64.zip"))
                self.assertFalse(row["downloadAuthorized"])
                self.assertFalse(row["mirrorAuthorized"])
        with self.assertRaises(ValueError):
            p.choose_fixed_major(report, "18")

        pg18_row = {"fileName": "postgis-bundle-pg18-3.6.2x64.zip", "pgMajor": "18",
                    "version": "3.6.2",
                    "sourceRelativePath": "pg18/postgis-bundle-pg18-3.6.2x64.zip",
                    "downloadAuthorized": False, "mirrorAuthorized": False}
        mutations = [
            ("missing_row", lambda r: r["latestBundleSelection"]["selected"].pop()),
            ("extra_pg18_row", lambda r: r["latestBundleSelection"]["selected"].append(pg18_row)),
            ("replace_14_with_18", lambda r: r["latestBundleSelection"]["selected"][0].update(pg18_row)),
            ("duplicate_major", lambda r: r["latestBundleSelection"]["selected"][1].update(
                {"pgMajor": "14", "fileName": "postgis-bundle-pg14-3.6.2x64.zip",
                 "sourceRelativePath": "pg14/postgis-bundle-pg14-3.6.2x64.zip"})),
            ("row_download_auth", lambda r: r["latestBundleSelection"]["selected"][0].update(
                {"downloadAuthorized": True})),
            ("selection_download_auth", lambda r: r["latestBundleSelection"].update(
                {"downloadAuthorized": True})),
            ("forged_path", lambda r: r["latestBundleSelection"]["selected"][2].update(
                {"sourceRelativePath": "pg16/../forged.zip"})),
            ("archive_path", lambda r: r["latestBundleSelection"]["selected"][2].update(
                {"sourceRelativePath": "pg16/archive/postgis-bundle-pg16-3.6.2x64.zip"})),
            ("wrong_mode_latest", lambda r: r["latestBundleSelection"].update(
                {"mode": "latest-per-supported-pg"})),
            ("wrong_mode_single", lambda r: r["latestBundleSelection"].update(
                {"mode": "single-newest-bundle"})),
            ("publication_auth", lambda r: r.update({"publicationAuthorized": True})),
        ]
        for label, mutation in mutations:
            with self.subTest(mutation=label):
                bad = copy.deepcopy(report)
                mutation(bad)
                with self.assertRaises(ValueError):
                    p.choose_fixed_major(bad, "14")

    def test_discover_latest_selection_and_fixed_contract_are_distinct(self):
        pages = {
            "": '<a href="pg14/">pg14/</a><a href="pg15/">pg15/</a><a href="pg18/">pg18/</a>',
            "pg14/": '<a href="postgis-bundle-pg14-3.6.1x64.zip">z</a>',
            "pg15/": '<a href="postgis-bundle-pg15-3.6.2x64.zip">z</a>',
            "pg18/": '<a href="postgis-bundle-pg18-3.6.2x64.zip">z</a>',
        }
        report = d.scan("osu-mirror", lambda dir_path: d.parse_listing(pages[dir_path]))
        selection = d.select_latest_bundles(report)
        report["latestBundleSelection"] = selection
        selected_majors = {row["pgMajor"] for row in selection["selected"]}
        self.assertTrue(selected_majors <= {"15", "16", "17", "18"})
        self.assertNotIn("14", selected_majors)
        self.assertEqual(selected_majors, {"15", "18"})
        url, row = p.choose_major(report, "15")
        self.assertEqual(row["version"], "3.6.2")
        self.assertIn("/pg15/", url)
        with self.assertRaisesRegex(ValueError, "OSGeo original-byte pilot DENY"):
            p.choose_major(report, "14")
        for pg in ("14", "15", "16", "17"):
            with self.subTest(pg=pg), self.assertRaises(ValueError):
                p.choose_fixed_major(report, pg)

    def test_per_major_run_remains_nonpublishing(self):
        with mock.patch.object(p, "read_original",
                               return_value=(123, "a" * 64)) as read, \
             mock.patch.object(p, "inspect",
                               return_value={"zipMembers": 42, "peAmd64Dlls": 2}):
            result = p.run(latest_snapshot(), pg_major="17")
        self.assertEqual(result["pgMajor"], "17")
        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assertFalse(result["downloadAuthorized"])
        self.assertFalse(result["publisherAuthorized"])
        self.assertFalse(result["mirrorAuthorized"])
        self.assertIn("/pg17/", read.call_args.args[0])

    def test_denies_redirect_escape(self):
        for url in ("http://download-cache.osgeo.org/postgis/windows/a.zip",
                    "https://evil.example/postgis/windows/a.zip",
                    "https://download-cache.osgeo.org@evil.example/postgis/windows/a.zip",
                    "https://download-cache.osgeo.org/postgis/windows/a.zip?token=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                p.safe_endpoint(url)

    def test_valid_amd64_postgis_pgrouting_archive(self):
        payload = fixture({"share/extension/postgis.control": b"comment = 'postgis'",
                           "share/extension/pgrouting.control": b"comment = 'pgrouting'",
                           "lib/postgis-3.dll": pe()})
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "bundle.zip"
            f.write_bytes(payload)
            result = p.inspect(f)
        self.assertEqual(result["peAmd64Dlls"], 1)
        self.assertTrue(result["pgroutingControl"])

    def test_rejects_traversal_wrong_arch_and_missing_component(self):
        cases = [
            {"../escape": b"x", "postgis.control": b"p", "pgrouting.control": b"r", "x.dll": pe()},
            {"postgis.control": b"p", "pgrouting.control": b"r", "x.dll": b"MZ wrong"},
            {"postgis.control": b"p", "x.dll": pe()},
        ]
        for members in cases:
            with tempfile.TemporaryDirectory() as d:
                f = Path(d) / "bundle.zip"
                f.write_bytes(fixture(members))
                with self.assertRaises(ValueError):
                    p.inspect(f)

    def test_transient_525_retry_preserves_exact_source_and_bytes(self):
        url = "https://download-cache.osgeo.org/postgis/windows/pg18/example.zip"
        payload = b"original-OSGeo-test-fixture"
        class Response(io.BytesIO):
            status = 200
            headers = {"Content-Length": str(len(payload))}
            def geturl(self):
                return url
        class Opener:
            def __init__(self):
                self.urls = []
            def open(self, request, timeout):
                self.urls.append(request.full_url)
                if len(self.urls) <= 2:
                    raise p.urllib.error.HTTPError(url, 525, "origin failure", {}, None)
                return Response(payload)
        opener = Opener()
        with tempfile.TemporaryDirectory() as d, mock.patch.object(p.time, "sleep"):
            path = Path(d) / "original.zip"
            size, sha = p.read_original(url, path, opener=opener)
            self.assertEqual(opener.urls, [url] * 3)
            self.assertEqual((size, sha), (len(payload), hashlib.sha256(payload).hexdigest()))
            self.assertEqual(path.read_bytes(), payload)

    def test_nontransient_404_and_bad_bytes_do_not_retry(self):
        url = "https://download-cache.osgeo.org/postgis/windows/pg18/example.zip"
        class NotFound:
            count = 0
            def open(self, request, timeout):
                self.count += 1
                raise p.urllib.error.HTTPError(url, 404, "not found", {}, None)
        opener = NotFound()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(p.urllib.error.HTTPError):
                p.read_original(url, Path(d) / "zip", opener)
        self.assertEqual(opener.count, 1)

        class Truncated(io.BytesIO):
            status = 200
            headers = {"Content-Length": "9"}
            def geturl(self):
                return url
        class BadBytes:
            count = 0
            def open(self, request, timeout):
                self.count += 1
                return Truncated(b"x")
        bad = BadBytes()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, "incomplete original ZIP"):
                p.read_original(url, Path(d) / "zip", bad)
        self.assertEqual(bad.count, 1)

    def test_no_publishing_actions(self):
        source = Path(p.__file__).read_text("utf-8")
        self.assertNotIn("workflow_dispatch", source)
        self.assertNotIn("gh release create", source)
        self.assertNotIn("Authorization:", source)


if __name__ == "__main__":
    unittest.main()
