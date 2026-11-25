#!/usr/bin/env python3
"""Regression guard for dependencies of the opt-in signed Release proposer."""
import unittest
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from contextlib import chdir
from pathlib import Path
import shutil
from unittest.mock import patch

from scripts import verified_release_record


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "sync-verified-release.yml"


class VerifiedReleaseWorkflowContractTests(unittest.TestCase):
    def test_verified_first_records_update_identity_and_candidate_index(self):
        workflow=WORKFLOW.read_text(encoding="utf-8")
        step=workflow.split("name: Update index only after complete signed",1)[1].split("      - name:",1)[0]
        code = textwrap.dedent(step.split("          python - <<'PY'\n", 1)[1].rsplit("          PY", 1)[0])
        update_indexes = compile(code, "sync-verified-release.yml: update indexes", "exec")

        def run_update(root, runner_tmp, name):
            # Each run gets the workflow's working directory, RUNNER_TEMP, and extension input.
            with chdir(root), patch.dict(os.environ, EXTENSION=name, RUNNER_TEMP=str(runner_tmp)), \
                    patch.object(sys, "path", [str(ROOT), *sys.path]):
                exec(update_indexes, {"__name__": "__main__"})

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner_tmp = root / "runner_temp"
            runner_tmp.mkdir()
            (root / "packages").mkdir()
            (root / "identities").mkdir()
            shutil.copy2(ROOT / "identities" / "pg_cron.json", root / "identities" / "pg_cron.json")
            base_idx = {
                "schemaVersion": 3, "identitiesDir": "identities", "packagesDir": "packages",
                "extensions": ["pg_cron"],
                "identities": [{
                    "name": "pg_cron", "path": "identities/pg_cron.json",
                    "intakeClass": "distributed", "ledgerPath": "packages/pg_cron.json",
                }],
            }
            (root / "identities" / "index.candidate.json").write_text(json.dumps(base_idx), "utf-8")
            for name in ("pgtap", "pg_variables", "pg_store_plans"):
                real_id = json.loads((ROOT / "identities" / f"{name}.json").read_text("utf-8"))
                real_id["research"]["evidenceUrls"] = ["https://github.com/" + real_id["upstreamRepository"]]
                id_path = root / "identities" / f"{name}.json"
                id_path.write_text(json.dumps(real_id, indent=2) + "\n", "utf-8")
                blob_sha = verified_release_record.identity_blob_sha(id_path)
                ledger = json.loads((ROOT / "packages" / f"{name}.json").read_text("utf-8"))
                cur = next(r for r in ledger["releases"] if r["releaseId"] == ledger["latestReleaseId"])
                expected_release_url = f"https://github.com/pgextwin/{name}/releases/tag/{cur['releaseTag']}"

                before_idx = (root / "identities" / "index.candidate.json").read_bytes()
                before_id = id_path.read_bytes()

                # Wrong ledger name fails closed.
                wrong = dict(ledger, name="other")
                (root / "packages" / f"{name}.json").write_text(json.dumps(wrong), "utf-8")
                (runner_tmp / "verified-catalog-record.json").write_text(
                    json.dumps({"identityBlobSha": blob_sha}), "utf-8"
                )
                with self.assertRaises(SystemExit) as rejected:
                    run_update(root, runner_tmp, name)
                self.assertNotIn(rejected.exception.code, (None, 0))
                self.assertEqual((root / "identities" / "index.candidate.json").read_bytes(), before_idx)
                self.assertEqual(id_path.read_bytes(), before_id)

                # Mismatched identityBlobSha fails closed.
                (root / "packages" / f"{name}.json").write_text(json.dumps(ledger), "utf-8")
                (runner_tmp / "verified-catalog-record.json").write_text(
                    json.dumps({"identityBlobSha": "0" * 40}), "utf-8"
                )
                with self.assertRaises(SystemExit) as rejected:
                    run_update(root, runner_tmp, name)
                self.assertNotIn(rejected.exception.code, (None, 0))
                self.assertEqual((root / "identities" / "index.candidate.json").read_bytes(), before_idx)
                self.assertEqual(id_path.read_bytes(), before_id)

                # Valid run updates identities/<name>.json and identities/index.candidate.json only.
                (runner_tmp / "verified-catalog-record.json").write_text(
                    json.dumps({"identityBlobSha": blob_sha}), "utf-8"
                )
                run_update(root, runner_tmp, name)
                updated_id = json.loads(id_path.read_text("utf-8"))
                self.assertEqual(updated_id["research"]["evidenceUrls"][0], expected_release_url)
                updated_idx = json.loads((root / "identities" / "index.candidate.json").read_text("utf-8"))
                self.assertIn(name, updated_idx["extensions"])
                self.assertFalse((root / "extensions").exists())
                self.assertFalse((root / "landscape").exists())
                self.assertFalse((root / "index.json").exists())

            before_idx = (root / "identities" / "index.candidate.json").read_bytes()
            with self.assertRaises(SystemExit) as rejected:
                run_update(root, runner_tmp, "unregistered")
            self.assertNotIn(rejected.exception.code, (None, 0))
            self.assertEqual((root / "identities" / "index.candidate.json").read_bytes(), before_idx)

    def test_schema_dependency_precedes_real_record_validation_without_duplicate_ci(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        install = workflow.index("name: Install Catalog JSON schema validator")
        assert_dependency = workflow.index(
            'python -m pip install --disable-pip-version-check "jsonschema>=4,<5"'
        )
        record_validation = workflow.index(
            "name: Validate proposed Catalog and Landscape locally"
        )
        self.assertLess(install, assert_dependency)
        self.assertLess(assert_dependency, record_validation)
        self.assertIn("python scripts/validate_catalog.py\n", workflow)
        self.assertNotIn("--verify-remote", workflow)
        self.assertNotIn("Run offline fail-closed test suite",workflow)
        required_ci=(ROOT/".github/workflows/validate.yml").read_text(encoding="utf-8")
        self.assertIn("python -m unittest discover -s tests -v",required_ci)

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

    def test_third_wave_requires_signed_first_record_verification(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("from scripts.verified_release_record import FIRST_RELEASE_SOURCES",workflow)
        self.assertIn("if name not in FIRST_RELEASE_SOURCES:",workflow)
        self.assertNotIn('if name not in {"pgtap", "pg_variables", "pg_store_plans"}',workflow)
        self.assertIn("        type: string",workflow)
        self.assertNotIn("        type: choice",workflow)
        self.assertIn("base_ledger_sha=MISSING", workflow)
        self.assertIn("base_identity_sha=MISSING", workflow)
        self.assertIn("base_index_sha=", workflow)
        self.assertIn('--record-output "packages/$EXTENSION.json"', workflow)
        self.assertIn("steps.verify.outputs.changed == 'true'", workflow)
        self.assertLess(workflow.index("Rehash all signed assets"),
                        workflow.index("Update index only after complete signed"))
        self.assertLess(workflow.index("Update index only after complete signed"),
                        workflow.index("Validate proposed Catalog and Landscape locally"))
        self.assertLess(workflow.index("Stage verified Catalog proposal artifact"),
                        workflow.index("Preserve immutable verification evidence"))
        self.assertIn('cp "$stage/packages/$EXTENSION.json" "packages/$EXTENSION.json"', workflow)
        self.assertIn('git add -- "${staged_candidates[@]}"', workflow)
        self.assertIn('LC_ALL=C sort', workflow)
        self.assertNotIn("extensions/", workflow)
        self.assertNotIn("landscape/", workflow)
        self.assertNotIn("gh pr merge", workflow)


    def test_proposal_shell_syntax_and_single_safe_noop_step(self):
        """Catch malformed YAML literal tails and missing nested bash 'fi' in PR."""
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for start, end in (
            ("      - name: Rehash all signed assets and independently authorize one Catalog record",
             "      - name: Update index only after complete signed"),
            ("      - name: Stage verified Catalog proposal artifact",
             "      - name: Preserve immutable verification evidence"),
        ):
            block = workflow.split(start, 1)[1].split(end, 1)[0]
            shell = block.split("        run: |\n", 1)[1]
            script = "\n".join(line[10:] for line in shell.splitlines()) + "\n"
            result = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

        step_name = "      - name: Create immutable verified-record PR with native PR CI (never auto-merge)"
        final_name = "      - name: Report record unchanged or proposer deliberately disabled"
        self.assertEqual(workflow.count(step_name), 1)
        self.assertEqual(workflow.count(final_name), 1)
        step = workflow.split(step_name, 1)[1].split(final_name, 1)[0]
        self.assertEqual(step.count("        run: |\n"), 1)
        shell = step.split("        run: |\n", 1)[1]
        self.assertTrue(all(not line or line.startswith("          ")
                            for line in shell.splitlines()),
                        "unindented workflow tail could be parsed as YAML metadata")
        script = "\n".join(line[10:] for line in shell.splitlines()) + "\n"
        result = subprocess.run(["bash", "-n"], input=script, text=True,
                                capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("identityBlobSha", script)
        self.assertIn('git diff --cached --quiet -- identities/index.candidate.json', script)
        self.assertIn("LC_ALL=C sort", script)



if __name__ == "__main__":
    unittest.main()
