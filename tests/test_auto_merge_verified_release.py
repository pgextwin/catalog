#!/usr/bin/env python3
"""Offline denial matrix for trusted-main, record-only Catalog auto merge."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "automerged", ROOT / "scripts" / "auto_merge_verified_release.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
TAG = "v2.10.14-windows.1"
BRANCH = "auto-catalog/plpgsql_check-" + TAG
SHA = "a" * 40


def good():
    pr = {"number": 21, "state": "open", "draft": False,
          "user": {"login": "github-actions[bot]"},
          "head": {"ref": BRANCH, "sha": SHA, "repo": {"full_name": "pgextwin/catalog"}},
          "base": {"ref": "main"}, "commits": 1}
    files = [{"filename": "extensions/plpgsql_check.json", "status": "modified"}]
    commits = [{"commit": {"message": "catalog: propose plpgsql_check " + TAG}}]
    return pr, files, commits


def policy():
    return {"schemaVersion": 1, "enabled": True,
            "mode": "POST_MANUAL_RELEASE_ONLY",
            "releasePolicy": "manual-dispatch",
            "automaticFormalRelease": False, "automaticCatalogMerge": True,
            "allowedExtensions": ["plpgsql_check"], "requiredCatalogWorkflow": "validate.yml",
            "requirePublishedPublicRelease": True,
            "requireBuildProvenanceAttestation": True, "requireSbomAttestation": True,
            "requireExactSHA256": True, "requireExactHeadRequiredChecks": True,
            "requireDedicatedMergeApp": True, "denyUnknownOrDuplicate": True,
            "notes": "manual Release downstream test"}


class CatalogAutomaticMerge(unittest.TestCase):
    def local(self):
        return {
            "schemaVersion": 1, "enabled": True, "extension": "plpgsql_check",
            "recordPath": "extensions/plpgsql_check.json",
            "requiredWorkflow": "validate.yml", "expectedRepository": "pgextwin/catalog",
            "centralPolicyRepository": "pgextwin/build", "notes": "fixture"}

    def test_production_configuration_remains_disabled(self):
        current = json.loads(
            (ROOT / "config" / "verified-release-auto-merge.json").read_text())
        self.assertIs(current["enabled"], False)
        with self.assertRaises(mod.AutoMergeDenied):
            mod.verify_policy(current, policy())

    def test_only_full_scoped_optin(self):
        mod.verify_policy(self.local(), policy())
        local = self.local()
        local["expectedRepository"] = "an-attacker/repo"
        with self.assertRaises(mod.AutoMergeDenied):
            mod.verify_policy(local, policy())
        p = policy()
        p["automaticFormalRelease"] = True
        with self.assertRaises(mod.AutoMergeDenied):
            mod.verify_policy(self.local(), p)
        for field, invalid in (
            ("enabled", False),
            ("mode", "UNATTENDED"),
            ("releasePolicy", "automatic"),
            ("automaticCatalogMerge", False),
            ("requireSbomAttestation", False),
            ("requireExactHeadRequiredChecks", False),
            ("allowedExtensions", ["plpgsql_check", "evil"])):
            with self.subTest(field=field):
                q = policy()
                q[field] = invalid
                with self.assertRaises(mod.AutoMergeDenied):
                    mod.verify_policy(self.local(), q)

    def test_owned_exact_record_only_pr(self):
        self.assertEqual(mod.inspect_pr(*good()), (21, SHA, BRANCH, TAG))
        pr, files, commits = good()
        files.append({"filename": ".github/workflows/validate.yml", "status": "added"})
        with self.assertRaises(mod.AutoMergeDenied):
            mod.inspect_pr(pr, files, commits)
        pr, files, commits = good()
        pr["user"]["login"] = "ShutenOishi"
        with self.assertRaises(mod.AutoMergeDenied):
            mod.inspect_pr(pr, files, commits)
        pr, files, commits = good()
        pr["head"]["sha"] = "not-sha"
        with self.assertRaises(mod.AutoMergeDenied):
            mod.inspect_pr(pr, files, commits)
        pr, files, commits = good()
        pr["commits"] = 2
        with self.assertRaises(mod.AutoMergeDenied):
            mod.inspect_pr(pr, files, commits)

    def test_never_cherry_pick_a_stale_ci_success(self):
        runs = [{"head_sha": SHA, "head_branch": BRANCH,
                 "event": "pull_request", "status": "completed",
                 "conclusion": "success", "created_at": "2026-10-09T01:00:00Z",
                 "id": 1}]
        mod.validate_run(runs, SHA, BRANCH)
        runs.append({"head_sha": SHA, "head_branch": BRANCH,
                     "event": "pull_request", "status": "completed",
                     "conclusion": "failure", "created_at": "2026-10-09T02:00:00Z",
                     "id": 2})
        with self.assertRaises(mod.AutoMergeDenied):
            mod.validate_run(runs, SHA, BRANCH)
        with self.assertRaises(mod.AutoMergeDenied):
            mod.validate_run([], SHA, BRANCH)
        # A manually dispatched check on the same SHA cannot bypass a native
        # pull_request action_required status or satisfy protected branch CI.
        with self.assertRaises(mod.AutoMergeDenied):
            mod.validate_run([{**runs[0], "event": "workflow_dispatch"}], SHA, BRANCH)


if __name__ == "__main__":
    unittest.main()
