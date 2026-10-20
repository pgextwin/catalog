#!/usr/bin/env python3
"""Prevent accidental resurrection of completed one-shot CLI publishers.

Historical tags, Release assets, release notes, source receipts, and tests
remain immutable in GitHub/Git history. This regression covers only
unnecessary live Actions entrypoints for already-published CLI versions.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


class RetiredOneShotCliWorkflows(unittest.TestCase):
    def test_v030_to_v032_one_shot_publishers_and_smokes_retired(self):
        names = ("cli-v030-release.yml", "cli-v031-release.yml",
                 "cli-v032-release.yml", "cli-v030-public-smoke.yml",
                 "cli-v031-public-smoke.yml", "cli-v032-public-smoke.yml",
                 "cli-v031-bilingual-notes.yml")
        for name in names:
            with self.subTest(name=name):
                self.assertFalse((WORKFLOWS / name).exists(),
                                 "obsolete CLI version-specific Actions entrypoint restored")

    def test_current_cli_and_catalog_security_checks_remain(self):
        for name in ("validate.yml", "cli-candidate.yml",
                     "cli-anonymous-latest.yml", "cli-signed-catalog-feed.yml",
                     "sync-verified-release.yml", "verify-manual-release.yml",
                     "notify-website.yml"):
            with self.subTest(name=name):
                self.assertTrue((WORKFLOWS / name).is_file())

    def test_old_plpgsql_only_catalog_ingestion_is_retired(self):
        self.assertFalse((WORKFLOWS / "sync-release.yml").exists())
        verified = (WORKFLOWS / "sync-verified-release.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/verify_signed_fleet_release.py", verified)
        self.assertIn("          - plpgsql_check", verified)
        for extension in ("pgtap", "pg_variables", "pg_store_plans"):
            self.assertIn("          - " + extension, verified)
        self.assertIn("permission-contents: write", verified)
        self.assertIn("permission-pull-requests: write", verified)

    def test_all_completed_cli_v01_v02_and_old_wave3_entrypoints_are_inert(self):
        obsolete = ("cli-preview-release.yml", "cli-public-smoke.yml",
                    "cli-v02-release.yml", "cli-v021-release.yml",
                    "cli-v022-release.yml", "cli-v02-public-smoke.yml",
                    "cli-v022-public-smoke.yml", "sync-wave3.yml")
        archive = ROOT / "tests" / "fixtures" / "historical-workflows"
        for name in obsolete:
            with self.subTest(name=name):
                self.assertFalse((WORKFLOWS / name).exists())
                self.assertTrue((archive / name).is_file())
        for name in ("cli-preview", "cli-v02", "cli-v021", "cli-v022"):
            self.assertTrue((ROOT / "config" / (name + "-release-intent.json")).is_file())
        self.assertTrue((ROOT / "scripts" / "propose_verified_wave3.py").is_file())
        self.assertTrue((ROOT / "tests" / "test_propose_verified_wave3.py").is_file())

    def test_historic_catalog_fleet14_and_bilingual_oneoffs_are_inert(self):
        # Exact original read-only canary and completed bilingual updater
        # remain testable, but must never mint another write workflow token.
        for name in ("catalog-fleet14-readonly-canary.yml",
                     "historical-release-bilingual.yml"):
            with self.subTest(name=name):
                self.assertFalse((WORKFLOWS / name).exists())
                self.assertTrue((ROOT / "tests/fixtures/historical-workflows" / name).is_file())
        for path in ("scripts/catalog_fleet14_readonly.py",
                     "scripts/bilingual_release_migration.py",
                     "config/historical-release-bilingual.json",
                     "tests/test_catalog_fleet14_readonly.py"):
            self.assertTrue((ROOT / path).is_file())
        # Keep the currently required Release verifier, managed Catalog
        # ingestion, website notification and read-only drift monitoring.
        for name in ("validate.yml", "sync-verified-release.yml",
                     "verify-manual-release.yml", "notify-website.yml",
                     "catalog-drift-readonly.yml", "issue112-p1-fleet-readonly.yml",
                     "cli-anonymous-latest.yml", "cli-signed-catalog-feed.yml"):
            self.assertTrue((WORKFLOWS / name).is_file())
        validate = (WORKFLOWS / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("unittest discover -s tests -v", validate)
        original = (ROOT / "tests/fixtures/historical-workflows/catalog-fleet14-readonly-canary.yml").read_text(encoding="utf-8")
        self.assertIn("DRY_RUN_FLEET14_METADATA_ONLY", original)
        self.assertNotIn("contents: write", original)
        original_notes = (ROOT / "tests/fixtures/historical-workflows/historical-release-bilingual.yml").read_text(encoding="utf-8")
        self.assertIn("Update ONLY existing public Release bodies", original_notes)
        self.assertNotIn("pull_request_target:", original_notes)

    def test_historic_release_metadata_is_preserved(self):
        for version in ("v030", "v031", "v032"):
            self.assertTrue((ROOT / "config" /
                             ("cli-" + version + "-release-intent.json")).is_file())
        for version in ("v0.3.0", "v0.3.1", "v0.3.2"):
            self.assertTrue((ROOT / "docs" /
                             ("cli-" + version + "-release-notes.md")).is_file())


if __name__ == "__main__":
    unittest.main()
