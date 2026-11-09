"""Hostile offline checks for the separate deny-first CLI Publisher."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "cli_external_get_formal_publisher", ROOT / "scripts/cli_external_get_formal_publisher.py")
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)
FILE = ROOT / "config/cli-external-get-formal-publisher-v1.json"


def active():
    policy = json.loads(FILE.read_text())
    policy.update(publishAuthorized=True, approvedVersion="0.3.10", environmentId=123456)
    return policy


def run():
    return {"id": 98765, "run_attempt": 1, "event": "workflow_run",
            "path": ".github/workflows/cli-release.yml",
            "repository": {"full_name": "pgextwin/catalog"},
            "head_branch": "main", "status": "in_progress"}


def approval(environment=123456, user=27071164):
    return [{"state": "approved", "user": {"login": "ShutenOishi", "id": user},
             "environments": [{"name": "cli-external-get-publisher", "id": environment}]}]


class FormalPublisher(unittest.TestCase):
    def test_disabled_policy_is_denied(self):
        policy = json.loads(FILE.read_text())
        policy.update(publishAuthorized=False, approvedVersion=None, environmentId=None)
        self.assertFalse(MOD.eligible(policy, "0.3.6"))
        self.assertFalse(MOD.eligible(policy, "0.3.10"))

    def test_real_policy_requires_same_run_owner_approval(self):
        policy = json.loads(FILE.read_text())
        version = "0.3.10"
        self.assertEqual(policy["environmentId"], 26611532853)
        self.assertTrue(MOD.eligible(policy, version))
        self.assertIn(
            {"extension": "vector", "pgMajor": "16",
             "sourceRepo": "portalcorp/pgvector_compiled", "releaseTag": "v0.16.105"},
            policy["approvedSources"])
        with self.assertRaises(MOD.Denied):
            MOD.eligible(policy, "0.3.6")
        with self.assertRaises(MOD.Denied):
            MOD.approve_same_run(policy, version, run(), [], 98765)

    def test_explicit_new_version_and_exact_scope(self):
        self.assertTrue(MOD.eligible(active(), "0.3.10"))
        for mutation in (
            {"approvedVersion": "0.3.11"}, {"approvedVersion": "0.3.9"}, {"approvedVersion": "0.3.7"},
            {"environmentId": None}, {"environmentId": 0},
            {"publishAuthorized": "true"}, {"mirrorAuthorized": True},
            {"redistributionAuthorized": True}, {"operation": "MIRROR"},
            {"approvedSources": []},
            {"approvedSources": [{"extension": "oracle_fdw", "pgMajor": "18",
                                  "sourceRepo": "laurenz/oracle_fdw", "releaseTag": "2.9.0"}]},
            {"approvedSources": active()["approvedSources"][:-1]}, {"ownerId": 111},
            {"repository": "wrong/repo"}, {"unexpected": True},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(MOD.Denied):
                    MOD.eligible({**active(), **mutation}, "0.3.10")

    def test_same_run_environment_review_required(self):
        self.assertTrue(MOD.approve_same_run(active(), "0.3.10", run(), approval(), 98765))
        bad = [
            (run(), [], 98765),
            (run(), approval(environment=999), 98765),
            (run(), approval(user=111), 98765),
            ({**run(), "run_attempt": 2}, approval(), 98765),
            ({**run(), "event": "workflow_dispatch"}, approval(), 98765),
            ({**run(), "path": "other.yml"}, approval(), 98765),
            ({**run(), "head_branch": "not-main"}, approval(), 98765),
            ({**run(), "status": "completed"}, approval(), 98765),
            (run(), approval(), 444),
        ]
        for source, reviews, run_id in bad:
            with self.subTest(source=source, reviews=reviews, run_id=run_id):
                with self.assertRaises(MOD.Denied):
                    MOD.approve_same_run(active(), "0.3.9", source, reviews, run_id)

    def test_json_duplicate_key_attack(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "p.json"
            p.write_text('{"publishAuthorized":false,"publishAuthorized":true}')
            with self.assertRaises(MOD.Denied):
                MOD.read_json(p)

    def test_workflow_proves_review_before_first_write(self):
        text = (ROOT / ".github/workflows/cli-release.yml").read_text()
        prepare, publish = text.split("\n  publish:", 1)
        self.assertIn("cli_external_get_formal_publisher.py policy", prepare)
        self.assertIn("CLI_FORMAL_PUBLISHER=DENY_NOT_ARMED", prepare)
        self.assertIn("environment: cli-external-get-publisher", publish)
        self.assertIn("actions: read", publish)
        self.assertIn("cli_external_get_formal_publisher.py approval", publish)
        self.assertIn("actions/runs/$env:GITHUB_RUN_ID/approvals", publish)
        self.assertLess(publish.index("cli_external_get_formal_publisher.py approval"),
                        publish.index("gh api --method POST repos/pgextwin/catalog/git/refs"))
        self.assertNotIn("workflow_dispatch:", text)
        self.assertNotIn("--clobber", publish)


if __name__ == "__main__":
    unittest.main()
