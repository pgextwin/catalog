"""Offline hostile boundary tests; never reach an external network."""
import copy
import io
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

    def test_no_publishing_actions(self):
        source = Path(p.__file__).read_text("utf-8")
        self.assertNotIn("workflow_dispatch", source)
        self.assertNotIn("gh release create", source)
        self.assertNotIn("Authorization:", source)


if __name__ == "__main__":
    unittest.main()
