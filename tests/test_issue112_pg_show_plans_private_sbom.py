"""Offline hostile tests of runner-local pg_show_plans SPDX and PE imports."""
import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue112_pg_show_plans_private_package import archive_members, create_bytes
from issue112_pg_show_plans_private_sbom import spdx_inventory, imported_dlls
from issue112_pg_show_plans_native_pilot import PINS

class PrivateSbomTests(unittest.TestCase):
    def setUp(self):
        self.files = {n: ("pinned-" + n).encode("utf-8") for n in PINS}
        self.dll = b"MZ" + b"x" * 2048
        self.members = archive_members(self.files, self.dll, 18)
        self.raw = create_bytes(self.members)

    def test_exact_zip_member_hash_coverage_without_authorization(self):
        doc = spdx_inventory(self.raw, self.members, 18, "2026-11-12T00:00:00Z")
        self.assertEqual(doc["spdxVersion"], "SPDX-2.3")
        self.assertEqual(doc["packages"][0]["versionInfo"], "v2.1.8")
        self.assertEqual(doc["packages"][0]["licenseDeclared"], "NOASSERTION")
        self.assertEqual(len(doc["files"]), len(self.members))
        self.assertEqual(len(doc["relationships"]), len(self.members) + 1)
        file_map = {f["fileName"][2:]: f for f in doc["files"]}
        self.assertEqual(set(file_map), set(self.members))
        for name, raw in self.members.items():
            self.assertEqual(file_map[name]["checksums"][1], {
                "algorithm": "SHA256",
                "checksumValue": hashlib.sha256(raw).hexdigest(),
            })
            self.assertEqual(file_map[name]["licenseConcluded"], "NOASSERTION")
        self.assertEqual(doc["packages"][0]["checksums"][0]["checksumValue"],
                         hashlib.sha256(self.raw).hexdigest())
        self.assertNotIn("publicGetAuthorized", doc)

    def test_tampered_byte_and_injected_member_denied(self):
        altered = dict(self.members)
        altered["LICENSE"] = b"modified"
        with self.assertRaises(ValueError):
            spdx_inventory(create_bytes(altered), self.members, 18)
        altered = dict(self.members)
        altered["evil.txt"] = b"unsigned"
        with self.assertRaises(ValueError):
            spdx_inventory(create_bytes(altered), self.members, 18)

    def test_wrong_major_and_noncanonical_archive_denied(self):
        with self.assertRaises(ValueError):
            spdx_inventory(self.raw, self.members, 19)
        with self.assertRaises(ValueError):
            spdx_inventory(self.raw + b"trailing", self.members, 18)

    def test_imports_observed_but_never_authorized(self):
        with patch("issue112_pg_show_plans_private_sbom.static_imports",
                   return_value=(["postgres.exe", "KERNEL32.dll"], ["delay.dll"])):
            result = imported_dlls(self.dll)
        self.assertEqual(result["staticImports"],
                         ["KERNEL32.dll", "postgres.exe"])
        self.assertEqual(result["delayImports"], ["delay.dll"])
        self.assertTrue(all(value is False for key, value in result.items()
                            if key.endswith("Verified") or key.endswith("Authorized")))

    def test_unparseable_or_missing_pe_imports_denied(self):
        with patch("issue112_pg_show_plans_private_sbom.static_imports",
                   return_value=([], [])):
            with self.assertRaises(ValueError):
                imported_dlls(self.dll)
        with patch("issue112_pg_show_plans_private_sbom.static_imports",
                   side_effect=ValueError("invalid PE")):
            with self.assertRaises(ValueError):
                imported_dlls(self.dll)

if __name__ == "__main__":
    unittest.main()
