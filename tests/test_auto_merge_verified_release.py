#!/usr/bin/env python3
"""Issue #75: strict shared signed Catalog auto-merge negative tests (offline)."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "signed_automerge", ROOT / "scripts" / "auto_merge_verified_release.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

TAG = "v2.10.15-windows.2"
SHA = "a" * 40
NAME = "plpgsql_check"
BRANCH = "auto-catalog/" + NAME + "-" + TAG


def local():
    return {
        "schemaVersion": 2, "enabled": True,
        "expectedRepository": "pgextwin/catalog",
        "centralPolicyRepository": "pgextwin/build",
        "requiredWorkflow": "validate.yml",
        "requiredCheckAppId": 15368,
        "expectedProposerLogin": "pgextwin-catalog-proposer[bot]",
        "expectedProposerBotId": 341259304,
        "notes": "test only",
    }


def central(mode="manual-dispatch"):
    return {
        "schemaVersion": 1, "enabled": True,
        "mode": ("POST_MANUAL_RELEASE_ONLY" if mode == "manual-dispatch"
                 else "POST_VERIFIED_RELEASE_ONLY"),
        "releasePolicy": mode,
        "automaticFormalRelease": mode == "automatic-signed-schedule",
        "automaticCatalogMerge": True,
        "allowedExtensions": sorted(mod.INTAKE_ALLOWED),
        "requiredCatalogWorkflow": "validate.yml",
        "requirePublishedPublicRelease": True,
        "requireBuildProvenanceAttestation": True,
        "requireSbomAttestation": True,
        "requireExactSHA256": True,
        "requireExactHeadRequiredChecks": True,
        "requireDedicatedMergeApp": True,
        "denyUnknownOrDuplicate": True,
        "notes": "test only",
    }


def pr_fixture(name=NAME, tag=TAG):
    branch = "auto-catalog/" + name + "-" + tag
    pr = {
        "number": 71, "state": "open", "draft": False,
        "user": {"login": "pgextwin-catalog-proposer[bot]", "type": "Bot",
                 "id": 341259304},
        "head": {"ref": branch, "sha": SHA,
                 "repo": {"full_name": "pgextwin/catalog"}},
        "base": {"ref": "main"}, "commits": 1
    }
    files = [{"filename": "extensions/" + name + ".json",
              "status": "modified"}]
    commits = [{"commit": {"message": "catalog: verified operator release " + name + " " + tag}}]
    return pr, files, commits


def run_fixture():
    return {
        "head_sha": SHA, "head_branch": BRANCH, "event": "pull_request",
        "status": "completed", "conclusion": "success", "run_attempt": 1,
        "created_at": "2026-10-24T11:00:00Z", "id": 100,
    }


def checks():
    return {"total_count": 2, "check_runs": [
        {"name": name, "head_sha": SHA, "status": "completed",
         "conclusion": "success", "app": {"id": 15368}}
        for name in sorted(mod.REQUIRED_CHECKS)
    ]}


class FleetSignedCatalogMerge(unittest.TestCase):
    def test_default_production_gate_remains_off(self):
        current = json.loads((ROOT / "config" / "verified-release-auto-merge.json").read_text())
        self.assertIs(current["enabled"], False)
        with self.assertRaises(mod.AutoMergeDenied):
            mod.verify_policy(current, central())
        workflow = (ROOT / ".github" / "workflows" /
                    "auto-merge-verified-release.yml").read_text()
        self.assertIn("vars.PGEXTWIN_CATALOG_AUTOMERGE_ENABLED == 'true'", workflow)
        self.assertIn("GH_READ_TOKEN: ", workflow)
        self.assertIn("GH_TOKEN: ", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("\npermissions:\n  contents: write", workflow)

    def test_two_explicit_source_modes_pass_only_with_consistent_flags(self):
        mod.verify_policy(local(), central())
        mod.verify_policy(local(), central("automatic-signed-schedule"))
        for mutate in (
            lambda a,b: a.update(enabled=False),
            lambda a,b: a.update(expectedRepository="evil/catalog"),
            lambda a,b: a.update(expectedProposerLogin="github-actions[bot]"),
            lambda a,b: a.update(expectedProposerBotId=0),
            lambda a,b: a.update(requiredCheckAppId=999),
            lambda a,b: b.update(enabled=False),
            lambda a,b: b.update(automaticCatalogMerge=False),
            lambda a,b: b.update(allowedExtensions=["plpgsql_check"]),
            lambda a,b: b["allowedExtensions"].append("evil"),
            lambda a,b: b.update(requireExactSHA256=False),
            lambda a,b: b.update(automaticFormalRelease=True),
            lambda a,b: b.update(releasePolicy="automatic-signed-schedule"),
            lambda a,b: b.update(mode="POST_VERIFIED_RELEASE_ONLY"),
        ):
            a, b = local(), central()
            mutate(a, b)
            with self.subTest(mutate=mutate), self.assertRaises(mod.AutoMergeDenied):
                mod.verify_policy(a, b)
        for mutate in (
            lambda b: b.update(automaticFormalRelease=False),
            lambda b: b.update(mode="POST_MANUAL_RELEASE_ONLY"),
            lambda b: b.update(requireDedicatedMergeApp=False),
        ):
            b = central("automatic-signed-schedule")
            mutate(b)
            with self.subTest(mutate=mutate), self.assertRaises(mod.AutoMergeDenied):
                mod.verify_policy(local(), b)

    def test_registered_record_only_signed_proposer_contract(self):
        for name in mod.INTAKE_ALLOWED:
            with self.subTest(name=name):
                pr, files, commits = pr_fixture(name, "v1.2-windows.1")
                out = mod.inspect_pr(pr, files, commits,
                                     proposer_login=local()["expectedProposerLogin"],
                                     proposer_id=local()["expectedProposerBotId"])
                self.assertEqual(out[3:], (name, "v1.2-windows.1"))
        p, f, c = pr_fixture()
        self.assertEqual(mod.inspect_pr(p, f, c,
                         proposer_login=local()["expectedProposerLogin"],
                                     proposer_id=local()["expectedProposerBotId"]),
                         (71, SHA, BRANCH, NAME, TAG))
        mutations = (
            lambda p,f,c: p["user"].update(login="ShutenOishi", type="User"),
            lambda p,f,c: p["user"].update(type="User"),
            lambda p,f,c: p["user"].update(id=1),
            lambda p,f,c: p["head"].update(sha="z"*40),
            lambda p,f,c: p["head"]["repo"].update(full_name="evil/catalog"),
            lambda p,f,c: p.update(commits=2),
            lambda p,f,c: p.update(draft=True),
            lambda p,f,c: f.append({"filename": ".github/workflows/validate.yml",
                                    "status": "modified"}),
            lambda p,f,c: f[0].update(status="added"),
            lambda p,f,c: c[0]["commit"].update(message="catalog: propose " + NAME + " " + TAG),
            lambda p,f,c: p["head"].update(ref="auto-catalog/evil-v1.0-windows.1"),
            lambda p,f,c: p["head"].update(ref="auto-catalog/" + NAME + "-../bad"),
        )
        for mutate in mutations:
            p, f, c = pr_fixture()
            mutate(p, f, c)
            with self.subTest(mutate=mutate), self.assertRaises(mod.AutoMergeDenied):
                mod.inspect_pr(p, f, c, proposer_login=local()["expectedProposerLogin"],
                                     proposer_id=local()["expectedProposerBotId"])

    def test_exact_native_ci_latest_attempt_and_app(self):
        mod.validate_run([run_fixture()], SHA, BRANCH)
        original = run_fixture()
        tests = [
            {**original, "event": "workflow_dispatch"},
            {**original, "run_attempt": 2},
            {**original, "conclusion": "failure"},
            {**original, "status": "queued", "conclusion": None},
        ]
        for item in tests:
            with self.subTest(item=item), self.assertRaises(mod.AutoMergeDenied):
                mod.validate_run([item], SHA, BRANCH)
        fail = {**original, "id": 101, "created_at": "2026-10-24T12:00:00Z",
                "conclusion": "failure"}
        with self.assertRaises(mod.AutoMergeDenied):
            mod.validate_run([original, fail], SHA, BRANCH)
        mod.validate_checks(checks(), SHA)
        for mutate in (
            lambda c: c["check_runs"][0]["app"].update(id=11),
            lambda c: c["check_runs"][0].update(status="in_progress", conclusion=None),
            lambda c: c["check_runs"].pop(),
            lambda c: c["check_runs"][0].update(head_sha="b"*40),
            lambda c: c["check_runs"][0].update(name="validate"),
            lambda c: c.update(total_count=101),
        ):
            obj = checks()
            mutate(obj)
            with self.subTest(mutate=mutate), self.assertRaises(mod.AutoMergeDenied):
                mod.validate_checks(obj, SHA)

    def test_signed_verifier_called_with_only_unprivileged_read_token(self):
        record_path = ROOT / "extensions" / (NAME + ".json")
        self.assertTrue(record_path.exists())
        existing = json.loads(record_path.read_text())
        revised = copy.deepcopy(existing)
        revised["latest"] = {"releaseTag": TAG}
        encoded = base64.b64encode(json.dumps(revised).encode()).decode()
        seen = []

        def fake_run(argv, cwd, env, text, capture_output):
            seen.append((argv, env.get("GH_TOKEN")))
            path = Path(cwd) / "extensions" / (NAME + ".json")
            path.write_text(json.dumps(revised))
            return Mock(returncode=0, stderr="")

        old_cwd = os.getcwd()
        try:
            os.chdir(ROOT)
            with patch.object(mod.subprocess, "run", side_effect=fake_run), \
                 patch.object(mod, "api",
                              return_value={"encoding": "base64", "content": encoded}):
                mod.verify_record(NAME, TAG, SHA, read_token="r"*32)
            self.assertEqual(len(seen), 1)
            self.assertEqual(seen[0][1], "r"*32)
            self.assertIn("verify_signed_fleet_release.py", " ".join(seen[0][0]))
            with patch.object(mod.subprocess, "run", side_effect=fake_run), \
                 patch.object(mod, "api",
                              return_value={"encoding": "base64",
                                            "content": base64.b64encode(b"{}").decode()}), \
                 self.assertRaises(mod.AutoMergeDenied):
                mod.verify_record(NAME, TAG, SHA, read_token="r"*32)
            with self.assertRaises(mod.AutoMergeDenied):
                mod.verify_record("unregistered", TAG, SHA, read_token="r"*32)
        finally:
            os.chdir(old_cwd)

    def test_no_merge_without_explicit_credentialed_activation(self):
        with patch.dict(os.environ, {
            "GITHUB_REPOSITORY": "pgextwin/catalog",
            "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "schedule",
            "PGEXTWIN_CATALOG_AUTOMERGE_ENABLED": "false",
        }):
            with self.assertRaises(mod.AutoMergeDenied):
                mod.perform(ROOT / "config/verified-release-auto-merge.json", dry_run=True)


if __name__ == "__main__":
    unittest.main()
