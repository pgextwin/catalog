#!/usr/bin/env python3
"""Issue #75: strict shared signed Catalog auto-merge negative tests (offline)."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
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
    def test_dedicated_existing_app_and_exact_live_scope(self):
        valid = {"total_count": 1, "repositories": [
            {"id": mod.CATALOG_ID, "full_name": mod.REPO, "private": False}]}
        mod.verify_app_scope(valid, mod.CATALOG_APP, mod.CATALOG_INSTALLATION)
        for slug, installation in (("pgextwin-publisher", mod.CATALOG_INSTALLATION),
                                   (mod.CATALOG_APP, "1"), (None, None)):
            with self.subTest(slug=slug), self.assertRaises(mod.AutoMergeDenied):
                mod.verify_app_scope(valid, slug, installation)
        for mutate in (
            lambda d: d.update(total_count=True),
            lambda d: d.update(total_count=2),
            lambda d: d["repositories"].append(copy.deepcopy(d["repositories"][0])),
            lambda d: d["repositories"][0].update(id=True),
            lambda d: d["repositories"][0].update(full_name="pgextwin/build"),
            lambda d: d["repositories"][0].update(private=True),
        ):
            d = copy.deepcopy(valid)
            mutate(d)
            with self.subTest(mutate=mutate), self.assertRaises(mod.AutoMergeDenied):
                mod.verify_app_scope(d, mod.CATALOG_APP, mod.CATALOG_INSTALLATION)

    def test_scope_probe_always_revokes_and_never_grants_merge_authority(self):
        env = {"GITHUB_REPOSITORY": mod.REPO, "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "workflow_run", "GITHUB_SHA": SHA}
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, env), \
             patch.object(mod, "check_app_scope"), \
             patch.object(mod, "api", return_value={"protected": True, "commit": {"sha": SHA}}), \
             patch.object(mod, "revoke_and_confirm") as revoke:
            path = Path(temp) / "proof.json"
            mod.probe_app(path)
            revoke.assert_called_once_with()
            d = json.loads(path.read_text())
            self.assertTrue(d["tokenRevokedHttp401"])
            for key in ("repositoryWritePerformed", "protectedMergePerformed",
                        "publicationAuthorized", "catalogMergeAuthorized"):
                self.assertIs(d[key], False)
            self.assertNotIn("token", d)
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, env), \
             patch.object(mod, "check_app_scope", side_effect=mod.AutoMergeDenied("scope")), \
             patch.object(mod, "revoke_and_confirm") as revoke:
            path = Path(temp) / "proof.json"
            with self.assertRaises(mod.AutoMergeDenied):
                mod.probe_app(path)
            revoke.assert_called_once_with()
            self.assertFalse(path.exists())

    def test_token_revocation_requires_actual_http401(self):
        with patch.object(mod.subprocess, "run", side_effect=[
                Mock(returncode=0), Mock(returncode=1, stderr="gh: Bad credentials (HTTP 401)")]):
            mod.revoke_and_confirm()
        for response in (Mock(returncode=0, stderr=""),
                         Mock(returncode=1, stderr="HTTP 403"),
                         Mock(returncode=1, stderr="network timeout")):
            with self.subTest(response=response), patch.object(mod.subprocess, "run", side_effect=[
                    Mock(returncode=0), response]), self.assertRaises(mod.AutoMergeDenied):
                mod.revoke_and_confirm()

    def test_all_noninstallation_reads_use_separate_read_credential(self):
        with patch.dict(os.environ, {"GH_TOKEN": "write-credential", "GH_READ_TOKEN": "r"*32}), \
             patch.object(mod.subprocess, "run", return_value=Mock(returncode=0, stdout="{}", stderr="")) as run:
            mod.api("repos/pgextwin/catalog/commits/" + SHA + "/check-runs")
            self.assertEqual(run.call_args.kwargs["env"]["GH_TOKEN"], "r"*32)
            mod.api("installation/repositories?per_page=100")
            self.assertEqual(run.call_args.kwargs["env"]["GH_TOKEN"], "write-credential")

    def test_github_wrapped_base64_policy_is_accepted_but_corruption_is_denied(self):
        raw = base64.b64encode(json.dumps(central()).encode()).decode()
        wrapped = "\n".join(raw[i:i+60] for i in range(0, len(raw), 60)) + "\n"
        self.assertEqual(mod.unpack_content({"encoding": "base64", "content": wrapped}), central())
        with self.assertRaises(ValueError):
            mod.unpack_content({"encoding": "base64", "content": wrapped + "!"})

    def test_workflow_reuses_existing_catalog_identity_and_separate_runtime_optin(self):
        workflow = (ROOT / ".github/workflows/auto-merge-verified-release.yml").read_text()
        self.assertNotIn("PGEXTWIN_CATALOG_MERGE_APP_PRIVATE_KEY", workflow)
        self.assertNotIn("PGEXTWIN_CATALOG_MERGE_APP_CLIENT_ID", workflow)
        self.assertEqual(workflow.count("private-key: ${{ secrets.PGEXTWIN_CATALOG_PROPOSER_APP_PRIVATE_KEY }}"), 2)
        self.assertEqual(workflow.count("repositories: catalog"), 2)
        self.assertIn("steps.app-token.outputs.app-slug", workflow)
        self.assertIn("steps.app-token.outputs.installation-id", workflow)
        self.assertIn("actions: read", workflow)
        self.assertIn("checks: read", workflow)
        self.assertNotIn("permission-actions: write", workflow)
        config = json.loads((ROOT / "config/verified-release-auto-merge.json").read_text())
        mod.validate_local_policy(config)

    def test_actual_deployment_policy_obeys_its_explicit_protected_optin(self):
        current = json.loads((ROOT / "config" / "verified-release-auto-merge.json").read_text())
        decision = mod.validate_local_policy(current)
        self.assertEqual(decision["enabled"], current["enabled"])
        self.assertIs(decision["catalogMergeAuthorized"], False)
        self.assertIs(decision["publicationAuthorized"], False)
        for mode in ("manual-dispatch", "automatic-signed-schedule"):
            if current["enabled"]:
                mod.verify_policy(current, central(mode))
            else:
                with self.assertRaises(mod.AutoMergeDenied):
                    mod.verify_policy(current, central(mode))
        workflow = (ROOT / ".github" / "workflows" /
                    "auto-merge-verified-release.yml").read_text()
        self.assertIn("vars.PGEXTWIN_CATALOG_AUTOMERGE_ENABLED == 'true'", workflow)
        self.assertIn("GH_READ_TOKEN: ", workflow)
        self.assertIn("GH_TOKEN: ", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("\npermissions:\n  contents: write", workflow)

    def test_disabled_historical_declaration_never_authorizes_a_merge(self):
        # Freeze the historical default as a fixture, not a forever-off rule on
        # the live deployment file. A protected activation still needs central
        # mode, runtime App opt-in, exact PR CI and independent signed assets.
        disabled = json.loads((ROOT / "tests/fixtures/catalog-auto-merge-disabled.json").read_text())
        self.assertIs(disabled["enabled"], False)
        decision = mod.validate_local_policy(disabled)
        self.assertFalse(decision["enabled"])
        self.assertFalse(decision["catalogMergeAuthorized"])
        for mode in ("manual-dispatch", "automatic-signed-schedule"):
            with self.assertRaises(mod.AutoMergeDenied):
                mod.verify_policy(disabled, central(mode))

    def test_local_transition_validates_both_modes_and_rejects_ambiguous_optins(self):
        for enabled in (False, True):
            projected = local()
            projected["enabled"] = enabled
            result = mod.validate_local_policy(projected)
            self.assertIs(result["enabled"], enabled)
            self.assertIs(result["catalogMergeAuthorized"], False)
            self.assertIs(result["publicationAuthorized"], False)
        for mutate in (
            lambda d: d.update(enabled=1),
            lambda d: d.update(enabled="true"),
            lambda d: d.update(enabled=None),
            lambda d: d.pop("enabled"),
            lambda d: d.update(schemaVersion=True),
            lambda d: d.update(notes=None),
            lambda d: d.update(expectedProposerBotId=True),
            lambda d: d.update(requiredCheckAppId=True),
            lambda d: d.update(expectedRepository="evil/catalog"),
            lambda d: d.update(extra=True),
        ):
            projected = local()
            mutate(projected)
            with self.subTest(mutate=mutate), self.assertRaises(mod.AutoMergeDenied):
                mod.validate_local_policy(projected)

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

    def test_first_release_is_not_record_only_but_is_strictly_scoped(self):
        p, f, c = pr_fixture("pgtap", "v1.3.4-windows.1")
        first_path = "extensions/pgtap.json"
        landscape_path = "landscape/extensions/pgtap.json"
        f = [{"filename": first_path, "status": "added"},
             {"filename": "index.json", "status": "modified"},
             {"filename": landscape_path, "status": "modified"}]
        self.assertEqual(mod.inspect_pr(
            p, f, c, proposer_login=local()["expectedProposerLogin"],
            proposer_id=local()["expectedProposerBotId"], initial=True)[3], "pgtap")
        mod.inspect_pr(p, f + [{"filename": "landscape/index.json", "status": "modified"}],
                       c, proposer_login=local()["expectedProposerLogin"],
                       proposer_id=local()["expectedProposerBotId"], initial=True)
        for invalid in (
            [{"filename": first_path, "status": "modified"}] + f[1:],
            f + [{"filename": "unrelated.json", "status": "modified"}],
            f + [{"filename": "landscape/index.json", "status": "removed"}],
            f + [f[0]],
            f[:2],
        ):
            with self.subTest(files=invalid), self.assertRaises(mod.AutoMergeDenied):
                mod.inspect_pr(p, invalid, c,
                               proposer_login=local()["expectedProposerLogin"],
                               proposer_id=local()["expectedProposerBotId"], initial=True)
        with self.assertRaises(mod.AutoMergeDenied):
            mod.inspect_pr(p, f, c,
                           proposer_login=local()["expectedProposerLogin"],
                           proposer_id=local()["expectedProposerBotId"], initial=False)
        with self.assertRaises(mod.AutoMergeDenied):
            mod.inspect_pr(*pr_fixture("pg_cron", "v1.0.0-windows.1"),
                           proposer_login=local()["expectedProposerLogin"],
                           proposer_id=local()["expectedProposerBotId"], initial=True)

    def test_first_release_projection_denies_unregistered_and_bad_identity(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "landscape" / "extensions").mkdir(parents=True)
            (root / "index.json").write_text(json.dumps({
                "schemaVersion": 2, "extensions": ["pg_cron"]}))
            (root / "landscape" / "index.json").write_text(json.dumps({
                "schemaVersion": 1, "extensions": ["pg_cron", "pgtap"]}))
            record = {
                "schemaVersion": 2, "name": "pgtap", "repository": "pgextwin/pgtap",
                "upstream": {"repository": "theory/pgtap"},
                "displayName": "pgTAP", "description": "PostgreSQL tests",
                "latest": {"publishedAt": "2026-10-25T00:00:00Z",
                           "releaseUrl": "https://github.com/pgextwin/pgtap/releases/tag/v1.3.4-windows.1"}
            }
            previous = os.getcwd()
            try:
                os.chdir(root)
                projected = mod.first_release_projection("pgtap", record)
                self.assertEqual(projected["index.json"]["extensions"], ["pg_cron", "pgtap"])
                self.assertEqual(projected["landscape/index.json"]["extensions"], ["pg_cron", "pgtap"])
                self.assertEqual(projected["landscape/extensions/pgtap.json"]["status"], "implemented")
                with self.assertRaises(mod.AutoMergeDenied):
                    mod.first_release_projection("pg_cron", record)
                bad = copy.deepcopy(record)
                bad["upstream"]["repository"] = "attacker/other"
                with self.assertRaises(mod.AutoMergeDenied):
                    mod.first_release_projection("pgtap", bad)
                (root / "index.json").write_text(json.dumps({
                    "schemaVersion": 2, "extensions": ["pg_cron", "pgtap"]}))
                with self.assertRaises(mod.AutoMergeDenied):
                    mod.first_release_projection("pgtap", record)
            finally:
                os.chdir(previous)

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
