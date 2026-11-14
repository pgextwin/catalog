"""Fail-closed offline fixture tests for nonpublishing pglogical dependencies."""
from __future__ import annotations

from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import issue112_pglogical_windows_dependency_resolution as audit
from test_issue112_pglogical_pe_import_inventory import fixture


class DependencyResolutionTests(unittest.TestCase):
    def test_candidate_search_does_not_prove_loader_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "pg"
            system = Path(tmp) / "System32"
            (root / "bin").mkdir(parents=True)
            (root / "lib").mkdir()
            system.mkdir()
            (root / "bin" / "libpq.dll").write_bytes(b"placeholder")
            (root / "bin" / "postgres.exe").write_bytes(b"placeholder")
            (system / "KERNEL32.dll").write_bytes(b"placeholder")
            originals = frozenset({"pglogical.dll", "pglogical_output.dll",
                                    "pglogical_create_subscriber.exe"})
            expectations = {
                "libpq.dll": "EDB_BIN",
                "postgres.exe": "EDB_BIN",
                "kernel32.dll": "UNRESOLVED",  # Case-sensitive test host
                "KERNEL32.dll": "WINDOWS_SYSTEM32",
                "api-ms-win-core-test-l1-1-0.dll": "API_SET_CONTRACT",
                "pglogical.dll": "PROVIDER_ORIGINAL",
                "notshipped.dll": "UNRESOLVED",
            }
            for name, category in expectations.items():
                with self.subTest(name=name):
                    self.assertEqual(audit.classify(name, root, system, originals)[0],
                                     category)

    def test_reject_unsafe_or_non_module_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("../../evil.dll", "C:/evil.dll", "bad.dll/../x.dll",
                         "", "shell32.so", "not-a-library"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    audit.classify(name, root, root, frozenset())

    def test_inventory_makes_no_authority_claim(self):
        binary = fixture()
        files = {k: binary for k in audit.ORIGINAL_PREFIX}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bin").mkdir()
            (root / "lib").mkdir()
            system = root / "System32"
            system.mkdir()
            (system / "kernel32.dll").write_bytes(b"test")
            result = audit.inventory(files, root, system)
        self.assertEqual(result["inspectedPEs"], 3)
        self.assertEqual(result["unresolved"], [])
        for flag in ("windowsLoaderClosure", "allRuntimeBranches",
                     "componentRightsAndNotices", "downloadAuthorized",
                     "mirrorAuthorized", "redistributionAuthorized",
                     "publisherAuthorized"):
            self.assertIs(result[flag], False)

    def test_unparsed_entries_carry_measured_diagnostics(self):
        oversized = b"MZ" + b"\x00" * audit.MAX_PE  # beyond the parser cap
        small_bad = b"tiny"
        files = {k: fixture() for k in audit.ORIGINAL_PREFIX}
        files["lib/pglogical.dll"] = oversized
        files["lib/pglogical_output.dll"] = small_bad
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bin").mkdir()
            (root / "lib").mkdir()
            system = root / "System32"
            system.mkdir()
            result = audit.inventory(files, root, system)
        by_id = {r["identity"]: r for r in result["entries"]}
        big = by_id["lib/pglogical.dll"]
        self.assertFalse(big["peParsed"])
        self.assertEqual(big["actualFileBytes"], len(oversized))
        self.assertIs(big["parserSizeExceeded"], True)
        self.assertTrue(big["reasonDetail"])
        small = by_id["lib/pglogical_output.dll"]
        self.assertFalse(small["peParsed"])
        self.assertEqual(small["actualFileBytes"], len(small_bad))
        self.assertIs(small["parserSizeExceeded"], False)
        self.assertIn("lib/pglogical.dll", result["unparsedOrUninspected"])
        self.assertIn("lib/pglogical_output.dll", result["unparsedOrUninspected"])

    def test_original_asset_missing_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                audit.inventory({"lib/pglogical.dll": fixture()}, root, root)

    def test_workflow_is_pr_only_and_no_write_capability(self):
        workflow = (ROOT / ".github/workflows/issue112-pglogical-dependency-resolution.yml").read_text()
        self.assertIn("pull_request:", workflow)
        self.assertIn("contents: read", workflow)
        for forbidden in ("workflow_dispatch:", "contents: write", "id-token: write",
                          "upload-artifact", "schedule:", "push:", "release:"):
            self.assertNotIn(forbidden, workflow)
        with patch.dict("os.environ", {"GITHUB_ACTIONS": "false"}, clear=True):
            with patch.object(sys, "argv", ["audit", "--pg", "18"]):
                with self.assertRaises(ValueError):
                    audit.main()


if __name__ == "__main__":
    unittest.main()
