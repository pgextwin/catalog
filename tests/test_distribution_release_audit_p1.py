#!/usr/bin/env python3
"""P1 GET-only and offline audit invocation safety, synthetic tests only."""
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import distribution_release_audit_p1 as audit
from distribution_manifest_v1 import Denied


class ReadOnlyP1Tests(unittest.TestCase):
    def test_gh_read_explicit_get_allowlist(self):
        forbidden = [
            ("api", "repos/pgextwin/example/actions/workflows/abc/dispatches"),
            ("api", "repos/pgextwin/example/releases", "-X", "POST"),
            ("release", "create", "newtag", "--repo", "pgextwin/example"),
            ("workflow", "run", "build.yml", "--repo", "pgextwin/example"),
            ("api", "repos/evil/example"),
            ("api", "repos/pgextwin/example/contents/.github/workflows/promote.yml?ref=main"),
            ("attestation", "verify", "binary.zip"),
            ("release", "download", "../bad", "--repo", "pgextwin/example", "--dir", "."),
            ("release", "download", "v3-windows.1", "--repo", "evil/example", "--dir", "."),
        ]
        with patch.object(audit.subprocess, "run") as proc:
            for args in forbidden:
                with self.subTest(args=args), self.assertRaises(Denied):
                    audit.gh_read(*args)
            proc.assert_not_called()

    def test_gh_read_restricted_get_only(self):
        result = type("Proc", (), {"returncode": 0, "stdout": "{}"})()
        with patch.object(audit.subprocess, "run", return_value=result) as called:
            self.assertEqual(audit.gh_read("api", "repos/pgextwin/example"), "{}")
            self.assertEqual(audit.gh_read("api", "repos/pgextwin/build"), "{}")
            self.assertEqual(audit.gh_read("api",
                "repos/pgextwin/catalog/contents/index.json?ref="+"a"*40), "{}")
            self.assertEqual(called.call_count, 3)
            for call in called.call_args_list:
                self.assertEqual(call.args[0][0:2], ("gh", "api"))
                self.assertFalse(call.kwargs["check"])

    def test_policy_requires_pinned_root_numeric_ids(self):
        policy = {
            "schemaVersion": "pgextwin-p1-readonly-policy/v1",
            "catalogCommitSha": "a"*40, "catalogDigests": {"index.json": "b"*64},
            "repoIds": {"example": 8001}, "releaseIds": {"example": 9001},
            "assetIds": {"example": {"some.zip": 10001}},
            "signerRepositoryId": 1405931353,
            "trustedSignerShas": ["c"*40], "approvedMajors": [14, 19],
            "pgEol": {"14": "2026-11-12", "19": "2031-11-01"},
            "rootSha256": "d"*64,
        }
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"policy.json"
            path.write_text(json.dumps(policy))
            self.assertEqual(audit.policy_load(path)["approvedMajors"], [14, 19])
            for key in ("rootSha256", "assetIds", "repoIds", "signerRepositoryId"):
                damaged = dict(policy)
                damaged.pop(key)
                path.write_text(json.dumps(damaged))
                with self.subTest(missing=key), self.assertRaises(Denied):
                    audit.policy_load(path)

    def test_no_administrator_proof_required_but_all_pins_still_mandatory(self):
        # Policy shape does not require a second administrator's signature.
        # Actual Release signatures and the TUF root are checked elsewhere.
        policy = {
            "schemaVersion": "pgextwin-p1-readonly-policy/v1",
            "catalogCommitSha": "a"*40,
            "catalogDigests": {"index.json": "b"*64},
            "repoIds": {"example": 8001},
            "releaseIds": {"example": 9001},
            "assetIds": {"example": {"SHA256SUMS.txt": 10001}},
            "signerRepositoryId": 1405931353,
            "trustedSignerShas": ["c"*40],
            "approvedMajors": [14],
            "pgEol": {"14": "2026-11-12"},
            "rootSha256": "d"*64,
        }
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"policy.json"
            path.write_text(json.dumps(policy))
            self.assertEqual(audit.policy_load(path), policy)
            for missing in ("catalogCommitSha", "catalogDigests", "repoIds",
                            "releaseIds", "assetIds", "trustedSignerShas",
                            "rootSha256"):
                altered = dict(policy)
                altered.pop(missing)
                path.write_text(json.dumps(altered))
                with self.subTest(missing=missing), self.assertRaises(Denied):
                    audit.policy_load(path)

    def test_offline_audit_must_never_contact_gh_when_root_missing(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)/"missing.json"
            with patch.object(audit.subprocess, "run") as run:
                self.assertEqual(audit.main(["--policy", str(p),
                                            "--snapshot", str(Path(folder)/"snapshot")]), 2)
                run.assert_not_called()

    def test_p1_runner_has_no_github_write_or_publisher_import(self):
        source = Path(audit.__file__).read_text(encoding="utf-8")
        for forbidden in ("fleet-publish-release", "publisher.py", "workflow_dispatch(",
                          "merge_pull_request(", "create_release(", "gh release create"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
