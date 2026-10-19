#!/usr/bin/env python3
"""Fail-closed tests for the no-App manual signed-Release Catalog PR handoff.

Static security tests; they never dispatch a workflow, fetch a Release, or
create a Catalog PR. The actual live release and signature proof is separate.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/verify-manual-release.yml").read_text(
    encoding="utf-8"
)
VERIFIER = (ROOT / "scripts/verify_signed_fleet_release.py").read_text(
    encoding="utf-8"
)


class ManualCatalogHandoff(unittest.TestCase):
    def test_main_only_and_read_only_no_app(self):
        self.assertIn("on:\n  workflow_dispatch:", WORKFLOW)
        self.assertIn("if: github.ref == 'refs/heads/main'", WORKFLOW)
        self.assertIn("permissions:\n  contents: read", WORKFLOW)
        self.assertIn("      attestations: read", WORKFLOW)
        self.assertIn("persist-credentials: false", WORKFLOW)
        for forbidden in (
            "contents: write", "pull-requests: write", "actions: write",
            "create-github-app-token", "secrets.", "gh pr create", "gh release create",
            "git push", "gh workflow run ", "\n  schedule:", "pull_request_target:",
            "continue-on-error:", "|| true", "always()",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, WORKFLOW)

    def test_full_rehash_signature_and_record_validation_before_artifact(self):
        steps = (
            "Run fail-closed offline verifier tests",
            "Independently verify immutable manual signed Release",
            "Validate verified proposed Catalog record and immutable public sources",
            "Report no-App GitHub-only protected PR handoff",
            "Store proposed verified Catalog record (not a PR)",
        )
        positions = [WORKFLOW.index(step) for step in steps]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('python -m pip install --disable-pip-version-check "jsonschema>=4,<5"', WORKFLOW)
        self.assertIn("--extension \"$EXTENSION\"", WORKFLOW)
        self.assertIn("--release-tag \"$RELEASE_TAG\"", WORKFLOW)
        self.assertIn('--record-output "extensions/$EXTENSION.json"', WORKFLOW)
        self.assertIn("python scripts/validate_landscape.py", WORKFLOW)
        self.assertIn("python scripts/validate_catalog.py --verify-remote", WORKFLOW)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", WORKFLOW)
        self.assertIn("name: verified-manual-release-record", WORKFLOW)
        self.assertIn("if-no-files-found: error", WORKFLOW)
        self.assertIn("native protected Catalog PR CI at the exact head", WORKFLOW)
        self.assertIn("without installing a Catalog proposer App", WORKFLOW)

    def test_verifier_rejects_unpublished_or_unsigned_candidate(self):
        for required in (
            "not an existing publicly published stable Release",
            "formal Promotion did not finish successfully",
            "gh(\"attestation\", \"verify\"",
            "verify_payload(folder, release, manifest, contract",
            "deny_catalog_rollback(original, release)",
            "recordChanged",
        ):
            with self.subTest(required=required):
                self.assertIn(required, VERIFIER)


if __name__ == "__main__":
    unittest.main()
