"""Offline guardrails for real Windows source-specific signed GET E2E."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
WF=(ROOT/".github/workflows/issue112-external-public-get-e2e.yml").read_text()
PS=(ROOT/"scripts/issue112-public-original-get-e2e.ps1").read_text()

class PublicGetGuard(unittest.TestCase):
    def test_genuine_original_source_only(self):
        for text in ("workflow_run:", "github.event.workflow_run.run_attempt == 1",
                     "github.event.workflow_run.conclusion == 'success'",
                     "github.event.workflow_run.event == 'push'",
                     "gh api repos/pgextwin/catalog/branches/main",
                     "issue112-public-original-get-e2e.ps1"):
            self.assertIn(text,WF)
        self.assertNotIn("workflow_dispatch:",WF)

    def test_source_selected_from_signed_postmerge_commit(self):
        for text in ("external/signed-direct-get/qualified_cohort/run-[0-9]+",
                     "external/signed-direct-get/qualified_cohort/latest.json",
                     'cohort="$(jq -r', 'provider="__DOLLAR__{cohort%%/*}"',
                     "NO_ATOMIC_SIGNED_CATALOG_LATEST_PIN_UPDATE; no provider GET",
                     "latest.json",
                     "case \"__DOLLAR__provider\" in qualified_cohort)"):
            self.assertIn(text.replace("__DOLLAR__","$"),WF)
        self.assertNotIn("workflow-verified",WF)

    def test_sigstore_still_required(self):
        self.assertIn("gh attestation verify $exe",WF)
        self.assertIn("PUBLIC_CLI_BYTES_AND_SIGSTORE=PASS",WF)
        self.assertIn("python scripts/validate_public_get_pin.py --catalog .",WF)

    def test_all_originals_exact_hash_and_cleanup(self):
        for text in ("[ValidateSet('qualified_cohort')]",
                     "GITHUB_EVENT_NAME -cne 'workflow_run'",
                     "download-all --source external --pg $pgArg",
                     "$pgArg='all'","Get-FileHash",
                     "REAL_WINDOWS_ORIGINAL_GET_ONLY_E2E=PASS",
                     "Remove-Item -LiteralPath $dest -Recurse -Force",
                     "pgextwin-external-latest-original-pins/v1",
                     "latest.records",
                     "latest.issuerRunId",
                     "Catalog latest admission Run is expired"):
            self.assertIn(text,PS)
        self.assertNotIn("--external-admission",PS)
        self.assertNotIn("--external-bundle",PS)
        self.assertNotIn("gh release create",PS)
        self.assertNotIn("actions/upload-artifact",PS)

if __name__=="__main__":
    unittest.main()
