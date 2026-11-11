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



def latest_snapshot():
    report = snapshot()
    selected = []
    for pg in ("14", "15", "16", "17", "18"):
        filename = f"postgis-bundle-pg{pg}-3.7.0x64.zip"
        selected.append({"fileName": filename, "pgMajor": pg,
                         "version": "3.7.0",
                         "sourceRelativePath": f"pg{pg}/{filename}",
                         "downloadAuthorized": False, "mirrorAuthorized": False})
    report["latestBundleSelection"]["mode"] = "latest-per-supported-pg"
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
        for pg in ("14", "15", "16", "17"):
            with self.subTest(pg=pg):
                url, row = p.choose_major(report, pg)
                self.assertEqual(url, (
                    f"https://download-cache.osgeo.org/postgis/windows/pg{pg}/"
                    f"postgis-bundle-pg{pg}-3.7.0x64.zip"))
                self.assertFalse(row["downloadAuthorized"])
                self.assertFalse(row["mirrorAuthorized"])
        with self.assertRaises(ValueError):
            p.choose_major(report, "18")

    def test_per_major_selector_denies_incomplete_duplicates_and_escalation(self):
        base = latest_snapshot()
        mutations = [
            lambda r: r["latestBundleSelection"]["selected"].pop(),
            lambda r: r["latestBundleSelection"]["selected"][1].update(
                {"pgMajor": "14", "fileName": "postgis-bundle-pg14-3.7.0x64.zip",
                 "sourceRelativePath": "pg14/postgis-bundle-pg14-3.7.0x64.zip"}),
            lambda r: r["latestBundleSelection"]["selected"][0].update(
                {"downloadAuthorized": True}),
            lambda r: r["latestBundleSelection"]["selected"][2].update(
                {"sourceRelativePath": "pg16/../forged.zip"}),
            lambda r: r["latestBundleSelection"].update(
                {"mode": "single-newest-bundle"}),
            lambda r: r.update({"publicationAuthorized": True}),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                report = copy.deepcopy(base)
                mutation(report)
                with self.assertRaises(ValueError):
                    p.choose_major(report, "14")

    def test_per_major_run_remains_nonpublishing(self):
        with mock.patch.object(p, "read_original",
                               return_value=(123, "a" * 64)) as read, \\
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
