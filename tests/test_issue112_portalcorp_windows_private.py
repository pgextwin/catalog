"""Offline adversarial fixtures for the private portalcorp original-Windows adapter."""
import io
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "portalcorp_private", ROOT / "scripts/issue112_portalcorp_windows_private.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def fake_pe(machine=0x8664):
    image = bytearray(256)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3c, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x84, machine)
    return bytes(image)


def original_zip(*, machine=0x8664, version="0.8.0", extra=None, omit_sql=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("lib/vector.dll", fake_pe(machine))
        z.writestr("share/extension/vector.control",
                   "default_version = '"+version+"'\n")
        if not omit_sql:
            z.writestr("share/extension/vector--0.8.0.sql",
                       "CREATE FUNCTION vector_in(cstring) RETURNS text AS 'x' LANGUAGE C;\n")
        if extra is not None:
            z.writestr(extra, b"hostile")
    return buffer.getvalue()


class PortalcorpOriginalTests(unittest.TestCase):
    def stage(self, contents, *, should_pass):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lib = root / "lib"
            ext = root / "share" / "extension"
            lib.mkdir()
            ext.mkdir(parents=True)
            if should_pass:
                report = module.inspect_and_stage(contents, lib, root / "share")
                self.assertFalse(report["getAuthorized"])
                self.assertFalse(report["mirrorAuthorized"])
                self.assertEqual("AMD64", report["peMachine"])
                self.assertTrue((lib / "vector.dll").exists())
                self.assertTrue((ext / "vector--0.8.0.sql").exists())
                with self.assertRaises(ValueError):
                    module.inspect_and_stage(contents, lib, root / "share")
            else:
                with self.assertRaises((ValueError, zipfile.BadZipFile)):
                    module.inspect_and_stage(contents, lib, root / "share")
                self.assertEqual([], list(lib.iterdir()))
                self.assertEqual([], list(ext.iterdir()))

    def test_accepts_exact_vetted_members_without_admission(self):
        self.stage(original_zip(), should_pass=True)

    def test_rejects_non_amd64_pe(self):
        self.stage(original_zip(machine=0x14c), should_pass=False)

    def test_rejects_wrong_extension_version(self):
        self.stage(original_zip(version="0.8.1"), should_pass=False)

    def test_rejects_archive_traversal(self):
        self.stage(original_zip(extra="../escape"), should_pass=False)

    def test_rejects_missing_sql(self):
        self.stage(original_zip(omit_sql=True), should_pass=False)

    def test_rejects_unmatched_pinned_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lib").mkdir()
            (root / "share" / "extension").mkdir(parents=True)
            with self.assertRaises(ValueError):
                module.inspect_and_stage(original_zip(), root / "lib",
                    root / "share", expected_sha=module.ASSET_SHA256)


if __name__ == "__main__":
    unittest.main()
