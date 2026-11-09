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
        for text in ("external/signed-direct-get/(pg_trickle|hypopg|portalcorp_pgvector|qualified_cohort)/run-[0-9]+",
                     'cohort="$(jq -r', 'provider="__DOLLAR__{cohort%%/*}"',
                     "Mixed signed cohorts in one commit; DENY",
                     'cohort="qualified_cohort/workflow-verified"'):
            self.assertIn(text.replace("__DOLLAR__","$"),WF)

    def test_sigstore_still_required(self):
        self.assertIn("gh attestation verify $exe",WF)
        self.assertIn("PUBLIC_CLI_BYTES_AND_SIGSTORE=PASS",WF)
        self.assertIn("python scripts/validate_public_get_pin.py --catalog .",WF)

    def test_all_originals_exact_hash_and_cleanup(self):
        for text in ("[ValidateSet('pg_trickle','hypopg','portalcorp_pgvector','qualified_cohort')]",
                     "GITHUB_EVENT_NAME -cne 'workflow_run'",
                     "download-all --source external --pg $pgArg",
                     "$pgArg='all'","$pgArg='18'","Get-FileHash",
                     "REAL_WINDOWS_ORIGINAL_GET_ONLY_E2E=PASS",
                     "Remove-Item -LiteralPath $dest -Recurse -Force",
                     "c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b",
                     "ac1114d1392494e688b5b6b6f151aebe6ccab2d8ae1a004ec510669c47ef3634",
                     "d23ea9ba7d064ee08e431b12ade50bed4b19a725b5f4df1e088e79e4af8d08ec",
                     "7afd7cda50050829787d4e901fc8292cf1eb2bc5ad59c996a92e414a1bead1f7"):
            self.assertIn(text,PS)
        self.assertNotIn("gh release create",PS)
        self.assertNotIn("actions/upload-artifact",PS)

if __name__=="__main__":
    unittest.main()
