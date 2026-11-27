#!/usr/bin/env python3
"""Fail-closed tests for the no-App manual signed-Release Catalog PR handoff.

Static security tests; they never dispatch a workflow, fetch a Release, or
create a Catalog PR. The actual live release and signature proof is separate.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = (ROOT / "scripts/verify_signed_fleet_release.py").read_text(
    encoding="utf-8"
)


class ManualCatalogHandoff(unittest.TestCase):
    def test_verifier_rejects_unpublished_or_unsigned_candidate(self):
        for required in (
            "not an existing publicly published stable Release",
            "formal Promotion did not finish successfully",
            'verified = gh(',
            '"attestation", "verify", str(package.zip_path)',
            "folder, release, manifest, contract, source_commit, active,",
            "deny_catalog_rollback(original, release)",
            "recordChanged",
        ):
            with self.subTest(required=required):
                self.assertIn(required, VERIFIER)
        self.assertIn("actual_sha = verify_release_attestations(", VERIFIER)
        self.assertIn("signer_sha == actual_sha", VERIFIER)


if __name__ == "__main__":
    unittest.main()
