#!/usr/bin/env python3
"""Offline hostile PE parser cases; no GitHub Release, original GET or upload."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_osgeo_dependency_inventory as deps


def fake_pe(name=b"geos_c.dll", delay=b"proj.dll"):
    data = bytearray(2048)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x8664, 1)
    struct.pack_into("<H", data, 0x94, 240)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20b)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112 + 8, 0x1100, 40)
    struct.pack_into("<II", data, optional + 112 + 13 * 8, 0x1140, 64)
    section = optional + 240
    struct.pack_into("<IIII", data, section + 8, 0x600, 0x1000, 0x600, 0x400)
    struct.pack_into("<I", data, 0x500 + 12, 0x1200)
    struct.pack_into("<II", data, 0x540, 1, 0x1220)
    data[0x600:0x600 + len(name) + 1] = name + b"\0"
    data[0x620:0x620 + len(delay) + 1] = delay + b"\0"
    return bytes(data)


class PeImportTests(unittest.TestCase):
    def test_static_and_delay_imports(self):
        self.assertEqual(deps.static_imports(fake_pe()),
                         (["geos_c.dll"], ["proj.dll"]))

    def test_import_rva_outside_sections_denied(self):
        data = bytearray(fake_pe())
        struct.pack_into("<I", data, 0x500 + 12, 0xF00000)
        with self.assertRaises(ValueError):
            deps.static_imports(data)

    def test_relative_path_in_dll_name_denied(self):
        with self.assertRaises(ValueError):
            deps.static_imports(fake_pe(name=b"..\\evil.dll"))

    def test_postgresql_server_exe_import_supported(self):
        self.assertEqual(deps.static_imports(fake_pe(name=b"postgres.exe"))[0],
                         ["postgres.exe"])

    def test_wrong_arch_denied(self):
        data = bytearray(fake_pe())
        struct.pack_into("<H", data, 0x84, 0x14c)
        with self.assertRaises(ValueError):
            deps.static_imports(data)

    def test_unterminated_descriptors_denied(self):
        data = bytearray(fake_pe())
        struct.pack_into("<I", data, 0x98 + 112 + 8 + 4, 20)
        with self.assertRaises(ValueError):
            deps.static_imports(data)

    def test_unbundled_triage_is_non_authorizing_and_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "triage.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("bundle/bin/postgis-3.dll",
                                fake_pe(name=b"postgres.exe", delay=b"kernel32.dll"))
                archive.writestr("bundle/bin/libcurl.dll",
                                fake_pe(name=b"libnghttp2-14.dll", delay=b"kernel32.dll"))
                archive.writestr("bundle/bin/postgisgui/libharfbuzz-icu-0.dll",
                                fake_pe(name=b"libicuuc74.dll", delay=b"libgailutil-18.dll"))
            result = deps.dependency_inventory(path)
            items = {x["name"]: x for x in result["unbundledImportTriage"]}
            self.assertEqual(len(items), 5)
            self.assertEqual(items["kernel32.dll"]["category"],
                             "WINDOWS_OS_DLL_NAME_ONLY_UNVERIFIED")
            self.assertEqual(items["postgres.exe"]["category"],
                             "POSTGRES_SERVER_HOST_NAME_ONLY_UNVERIFIED")
            self.assertEqual(items["libnghttp2-14.dll"]["category"],
                             "UNRESOLVED_NONBUNDLED_COMPONENT")
            self.assertFalse(items["libnghttp2-14.dll"]["onlyReferencedFromGuiDirectory"])
            self.assertEqual(items["libnghttp2-14.dll"]["referencedBy"],
                             ["bundle/bin/libcurl.dll"])
            for name in ("libicuuc74.dll", "libgailutil-18.dll"):
                self.assertTrue(items[name]["onlyReferencedFromGuiDirectory"])
                self.assertFalse(items[name]["resolvedOnTargetWindows"])
            self.assertEqual(result["unresolvedNonbundledImports"],
                             ["libgailutil-18.dll", "libicuuc74.dll", "libnghttp2-14.dll"])
            self.assertFalse(result["targetWindowsImportResolutionVerified"])
            self.assertFalse(result["dynamicDependenciesVerified"])
            self.assertFalse(result["downloadAuthorized"])

    def test_server_reachability_exposes_transitive_missing_and_excludes_gui(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "core.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("bundle/lib/postgis-3.dll",
                                 fake_pe(name=b"libproj_9.dll", delay=b"postgres.exe"))
                archive.writestr("bundle/bin/libproj_9.dll",
                                 fake_pe(name=b"libcurl.dll", delay=b"kernel32.dll"))
                archive.writestr("bundle/bin/libcurl.dll",
                                 fake_pe(name=b"libnghttp2-14.dll", delay=b"libbrotlidec.dll"))
                archive.writestr("bundle/lib/libpgrouting-4.0.dll",
                                 fake_pe(name=b"kernel32.dll", delay=b"postgres.exe"))
                archive.writestr("bundle/bin/postgisgui/libbrotlidec.dll",
                                 fake_pe(name=b"kernel32.dll"))
                archive.writestr("bundle/bin/postgisgui/libgail.dll",
                                 fake_pe(name=b"libgailutil-18.dll", delay=b"libicuuc74.dll"))
            scope = deps.dependency_inventory(path)["coreServerImportPaths"]
            names = {x["name"]: x for x in scope["unresolvedThirdPartyImportPaths"]}
            self.assertEqual(set(names), {"libnghttp2-14.dll", "libbrotlidec.dll"})
            self.assertEqual(names["libnghttp2-14.dll"]["chain"],
                             ["postgis-3.dll", "libproj_9.dll",
                              "libcurl.dll", "libnghttp2-14.dll"])
            self.assertTrue(names["libbrotlidec.dll"]["presentOnlyInExcludedGuiTree"])
            self.assertNotIn("libgailutil-18.dll", names)
            self.assertNotIn("libicuuc74.dll", names)
            self.assertTrue(scope["staticServerGraphTraversed"])
            self.assertFalse(scope["effectiveWindowsLoaderResolutionVerified"])
            self.assertFalse(scope["downloadAuthorized"])

    def test_server_duplicate_name_denied_and_missing_root_reported(self):
        duplicate = [
            {"path": "bundle/bin/libcurl.dll", "analysis": "AMD64_PE32_PLUS"},
            {"path": "bundle/lib/libcurl.dll", "analysis": "AMD64_PE32_PLUS"},
        ]
        with self.assertRaisesRegex(ValueError, "Ambiguous server DLL"):
            deps.core_server_import_paths(duplicate)
        scope = deps.core_server_import_paths([])
        self.assertEqual(scope["missingRoots"],
                         ["libpgrouting-<version>.dll", "postgis-3.dll"])
        self.assertFalse(scope["staticServerGraphTraversed"])


    def test_pg14_17_versioned_pgrouting_is_root_not_pg18_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pg16-physical-bundle.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("bundle/lib/postgis-3.dll",
                                 fake_pe(name=b"kernel32.dll", delay=b"postgres.exe"))
                archive.writestr("bundle/lib/libpgrouting-3.7.dll",
                                 fake_pe(name=b"postgres.exe", delay=b"kernel32.dll"))
            scope = deps.dependency_inventory(path)["coreServerImportPaths"]
            self.assertEqual(scope["roots"],
                             ["postgis-3.dll", "libpgrouting-3.7.dll"])
            self.assertEqual(scope["selectedVersionedPgRoutingServerDll"],
                             "libpgrouting-3.7.dll")
            self.assertEqual(scope["missingRoots"], [])
            self.assertEqual(scope["reachableServerModuleCount"], 2)
            self.assertTrue(scope["staticServerGraphTraversed"])
            self.assertFalse(scope["effectiveWindowsLoaderResolutionVerified"])
            self.assertFalse(scope["downloadAuthorized"])

    def test_ambiguous_versioned_routing_roots_fail_closed(self):
        records = [
            {"path": f"bundle/lib/libpgrouting-{ver}.dll",
             "analysis": "AMD64_PE32_PLUS", "staticImports": [],
             "delayImports": []} for ver in ("3.7", "4.0")]
        with self.assertRaisesRegex(ValueError, "Ambiguous versioned pgRouting"):
            deps.core_server_import_paths(records)

    def test_gui_only_routing_or_unsafe_name_never_fills_server_root(self):
        records = [
            {"path": "bundle/bin/postgisgui/libpgrouting-4.0.dll",
             "analysis": "AMD64_PE32_PLUS", "staticImports": [],
             "delayImports": []},
            {"path": "bundle/lib/libpgrouting-untrusted.dll",
             "analysis": "AMD64_PE32_PLUS", "staticImports": [],
             "delayImports": []},
        ]
        scope = deps.core_server_import_paths(records)
        self.assertIsNone(scope["selectedVersionedPgRoutingServerDll"])
        self.assertIn("libpgrouting-<version>.dll", scope["missingRoots"])
        self.assertFalse(scope["staticServerGraphTraversed"])
        self.assertFalse(scope["independentSignedAdmission"])
        self.assertFalse(scope["downloadAuthorized"])

    def test_unknown_unbundled_dll_stays_unresolved(self):
        result = deps.triage_unbundled_imports(
            [{"analysis": "AMD64_PE32_PLUS", "path": "bundle/lib/extension.dll",
              "notBundledImports": ["mystery.dll"]}], {"mystery.dll"})
        self.assertEqual(result[0]["category"], "UNRESOLVED_NONBUNDLED_COMPONENT")
        self.assertFalse(result[0]["resolvedOnTargetWindows"])

    def test_orphan_import_cannot_be_invented(self):
        with self.assertRaisesRegex(ValueError, "lacks referencing DLL"):
            deps.triage_unbundled_imports([], {"missing.dll"})

    def test_report_cannot_authorize_and_requires_no_mirror(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("bundle/lib/postgis-3.dll", fake_pe())
                archive.writestr("bundle/bin/geos_c.dll", fake_pe(name=b"kernel32.dll"))
            r = deps.dependency_inventory(path)
            self.assertEqual(r["dllCount"], 2)
            self.assertEqual(r["parsedPeCount"], 2)
            self.assertIn("proj.dll", r["importsNotInBundle"])
            self.assertNotIn("geos_c.dll", r["importsNotInBundle"])
            for flag in ("dynamicDependenciesVerified", "targetWindowsImportResolutionVerified",
                         "thirdPartyNoticesVerified",
                         "sourceToBinaryProvenanceVerified", "independentSignedAdmission",
                         "downloadAuthorized", "mirrorAuthorized", "publisherAuthorized"):
                self.assertIs(r[flag], False)


if __name__ == "__main__":
    unittest.main()
