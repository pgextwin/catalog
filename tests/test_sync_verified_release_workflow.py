#!/usr/bin/env python3
"""Regression guard for dependencies of the opt-in signed Release proposer."""
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "sync-verified-release.yml"


class VerifiedReleaseWorkflowContractTests(unittest.TestCase):
    def test_jsonschema_installed_before_offline_tests_and_record_validation(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        install = workflow.index("name: Install Catalog JSON schema validator")
        assert_dependency = workflow.index(
            'python -m pip install --disable-pip-version-check "jsonschema>=4,<5"'
        )
        offline_tests = workflow.index("name: Run offline fail-closed test suite")
        record_validation = workflow.index(
            "name: Validate proposed record against Catalog schema and live sources"
        )
        self.assertLess(install, assert_dependency)
        self.assertLess(assert_dependency, offline_tests)
        self.assertLess(offline_tests, record_validation)

    def test_proposer_stays_opt_in_and_never_merges_pr(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "steps.verify.outputs.changed == 'true' && "
            "vars.PGEXTWIN_CATALOG_PROPOSER_ENABLED == 'true'",
            workflow,
        )
        self.assertIn("repositories: catalog", workflow)
        self.assertIn("permission-contents: write", workflow)
        self.assertIn("permission-pull-requests: write", workflow)
        self.assertIn("gh pr create --repo", workflow)
        self.assertNotIn("gh pr merge", workflow)


if __name__ == "__main__":
    unittest.main()
