#!/usr/bin/env python3
"""Regression guard for dependencies of the opt-in signed Release proposer."""
import unittest
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "sync-verified-release.yml"


class VerifiedReleaseWorkflowContractTests(unittest.TestCase):
    def test_verified_first_records_update_both_indexes_and_landscape(self):
        workflow=WORKFLOW.read_text(encoding="utf-8")
        step=workflow.split("name: Update index only after complete signed",1)[1].split("      - name:",1)[0]
        code=textwrap.dedent(step.split("          python - <<'PY'\n",1)[1].rsplit("          PY",1)[0])
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"extensions").mkdir()
            (root/"landscape/extensions").mkdir(parents=True)
            for path in (root/"index.json",root/"landscape/index.json"):
                path.write_text(json.dumps({"extensions":["pg_cron"]}))
            for name in ("pgtap","pg_variables","pg_store_plans"):
                record={"schemaVersion":2,"name":name,"displayName":name,
                        "description":"Verified test record",
                        "upstream":{"repository":"upstream/"+name},
                        "latest":{"publishedAt":"2026-10-22T00:00:00Z",
                                  "releaseUrl":"https://github.com/pgextwin/"+name+"/releases/tag/v1.0-windows.1"}}
                (root/"extensions"/(name+".json")).write_text(json.dumps(record))
                before=(root/"index.json").read_bytes()
                wrong=dict(record,name="other")
                (root/"extensions"/(name+".json")).write_text(json.dumps(wrong))
                rejected=subprocess.run([sys.executable,"-c",code],cwd=root,
                    env={**os.environ,"EXTENSION":name},capture_output=True,text=True)
                self.assertNotEqual(rejected.returncode,0)
                self.assertEqual((root/"index.json").read_bytes(),before)
                self.assertFalse((root/"landscape/extensions"/(name+".json")).exists())
                (root/"extensions"/(name+".json")).write_text(json.dumps(record))
                done=subprocess.run([sys.executable,"-c",code],cwd=root,
                    env={**os.environ,"EXTENSION":name},capture_output=True,text=True)
                self.assertEqual(done.returncode,0,done.stderr)
                landscape=json.loads((root/"landscape/extensions"/(name+".json")).read_text())
                self.assertEqual(landscape["status"],"implemented")
                self.assertEqual(landscape["pgextwinCatalogName"],name)
                self.assertEqual(landscape["evidenceUrls"][0],record["latest"]["releaseUrl"])
                self.assertEqual(json.loads((root/"index.json").read_text())["extensions"],
                                 json.loads((root/"landscape/index.json").read_text())["extensions"])
            before=(root/"index.json").read_bytes()
            missing=subprocess.run([sys.executable,"-c",code],cwd=root,
                env={**os.environ,"EXTENSION":"unregistered"},capture_output=True,text=True)
            self.assertNotEqual(missing.returncode,0)
            self.assertEqual((root/"index.json").read_bytes(),before)

    def test_schema_dependency_precedes_real_record_validation_without_duplicate_ci(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        install = workflow.index("name: Install Catalog JSON schema validator")
        assert_dependency = workflow.index(
            'python -m pip install --disable-pip-version-check "jsonschema>=4,<5"'
        )
        record_validation = workflow.index(
            "name: Validate proposed record against Catalog schema and live sources"
        )
        self.assertLess(install, assert_dependency)
        self.assertLess(assert_dependency, record_validation)
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
        for name in ("pgtap", "pg_variables", "pg_store_plans"):
            self.assertIn("          - " + name + "\n", workflow)
        self.assertIn("base_record_sha=MISSING", workflow)
        self.assertIn("base_index_sha=", workflow)
        self.assertIn("steps.verify.outputs.changed == 'true'", workflow)
        self.assertLess(workflow.index("Rehash all signed assets"),
                        workflow.index("Update index only after complete signed"))
        self.assertLess(workflow.index("Update index only after complete signed"),
                        workflow.index("Validate proposed record against Catalog"))
        self.assertIn('if [[ "$BASE_RECORD_SHA" == MISSING ]]', workflow)
        self.assertIn('cp ../index.json index.json', workflow)
        self.assertIn('git add -- "extensions/$EXTENSION.json" index.json', workflow)
        self.assertNotIn("gh pr merge", workflow)


if __name__ == "__main__":
    unittest.main()
