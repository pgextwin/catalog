#!/usr/bin/env python3
"""Offline adversarial OSGeo bundle licensing inventory tests; no network GET."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_osgeo_rights_audit as audit


def amd64_dll():
    raw = bytearray(128)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3c, 64)
    raw[64:70] = b"PE\0\0\x64\x86"
    return bytes(raw)


def build(path, missing=None, extra=None):
    contents = {
        audit.ROOT + "postgis.control": b"comment",
        audit.ROOT + "pgrouting.control": b"comment",
        audit.ROOT + "lib/postgis-3.dll": amd64_dll(),
        audit.ROOT + "lib/libpgrouting-4.0.dll": amd64_dll(),
        audit.LICENSES[0]: b"GNU GENERAL PUBLIC LICENSE\nVersion 2",
        audit.LICENSES[1]: b"COPYING license test",
        audit.LICENSES[2]: b"GDAL license test",
    }
    if missing:
        contents.pop(missing)
    if extra:
        contents.update(extra)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in contents.items():
            archive.writestr(name, value)


class RightsAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.original = Path(self.temp.name) / "original.zip"

    def test_inventory_always_nonpublishing(self):
        build(self.original)
        result = audit.audit_archive(self.original)
        self.assertEqual(len(result["licenseFiles"]), 3)
        self.assertEqual(result["dllCount"], 2)
        for key in ("licenseClosureVerified", "dynamicDependenciesVerified",
                    "sourceToBinaryProvenanceVerified", "independentSignedAdmission",
                    "downloadAuthorized", "redistributionAuthorized",
                    "mirrorAuthorized", "publisherAuthorized"):
            self.assertIs(result[key], False, key)

    def test_per_dll_exact_byte_receipts_are_non_authorizing(self):
        import hashlib
        build(self.original, extra={
            audit.ROOT + "bin/postgisgui/lib/postgis-3.dll": b"GUI DLL",
            audit.ROOT + "lib/libproj_9.dll": b"UNVERIFIED LIB",
        })
        result = audit.audit_archive(self.original)
        rows = result["dllComponentIntakeReceipts"]
        self.assertEqual(result["dllCount"], len(rows))
        self.assertEqual([r["path"] for r in rows],
                         sorted(r["path"] for r in rows))
        self.assertIs(result["allComponentLicensesAndNoticesVerified"], False)
        gui = [r for r in rows if r["inGuiDirectory"]]
        self.assertEqual(len(gui), 1)
        self.assertEqual(gui[0]["sha256"],
                         hashlib.sha256(b"GUI DLL").hexdigest())
        self.assertFalse(next(r for r in rows
                              if r["path"].endswith("libproj_9.dll")
                              )["inGuiDirectory"])
        # A duplicated DLL basename cannot merge separate binary evidence.
        self.assertEqual(len({r["path"] for r in rows}), len(rows))
        for row in rows:
            self.assertEqual(len(row["sha256"]), 64)
            for flag in ("componentIdentityVerified",
                         "componentLicenseNoticeVerified",
                         "exactSourceToBinaryProvenanceVerified"):
                self.assertIs(row[flag], False)

    def test_dll_byte_change_changes_exact_member_receipt(self):
        import hashlib
        name = audit.ROOT + "lib/libpgrouting-4.0.dll"
        build(self.original)
        original_row = next(r for r in audit.audit_archive(
            self.original)["dllComponentIntakeReceipts"] if r["path"] == name)
        build(self.original, extra={name: amd64_dll() + b"changed"})
        changed_row = next(r for r in audit.audit_archive(
            self.original)["dllComponentIntakeReceipts"] if r["path"] == name)
        self.assertNotEqual(original_row["sha256"], changed_row["sha256"])
        self.assertEqual(changed_row["sha256"],
                         hashlib.sha256(amd64_dll() + b"changed").hexdigest())
        self.assertFalse(changed_row["componentLicenseNoticeVerified"])

    def test_dll_named_after_a_license_is_not_automatically_cleared(self):
        build(self.original, extra={
            audit.ROOT + "bin/mit-license.dll": b"not-license-evidence"})
        rows = audit.audit_archive(self.original)["dllComponentIntakeReceipts"]
        row = next(r for r in rows if r["path"].endswith("mit-license.dll"))
        self.assertFalse(row["componentIdentityVerified"])
        self.assertFalse(row["componentLicenseNoticeVerified"])

    def test_each_missing_license_denied(self):
        for name in audit.LICENSES:
            build(self.original, missing=name)
            with self.assertRaises(ValueError):
                audit.audit_archive(self.original)

    def test_archive_traversal_denied(self):
        build(self.original, extra={"../escape": b"bad"})
        with self.assertRaises(ValueError):
            audit.audit_archive(self.original)

    def test_missing_native_library_denied(self):
        build(self.original, missing=audit.ROOT + "lib/postgis-3.dll")
        with self.assertRaises(ValueError):
            audit.audit_archive(self.original)

    def test_oversized_license_denied(self):
        build(self.original, extra={
            audit.LICENSES[0]: b"A" * (audit.MAX_LICENSE_BYTES + 1)})
        with self.assertRaises(ValueError):
            audit.audit_archive(self.original)

    def test_exact_official_origin_and_hash_pinned(self):
        self.assertEqual(audit.SIZE, 83_320_975)
        self.assertEqual(len(audit.SHA256), 64)
        self.assertTrue(audit.ORIGIN.startswith(
            "https://download-cache.osgeo.org/postgis/windows/pg18/"))


if __name__ == "__main__":
    unittest.main()
