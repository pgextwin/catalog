"""Run the actual offline inventory CLI and validate its JSON output in CI."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/distribution_offline_major_inventory_v1.py"


class InventoryCliOutputTests(unittest.TestCase):
    def test_actual_cli_json_70_rows_and_denial(self):
        p = subprocess.run([sys.executable, str(SCRIPT)], cwd=ROOT,
                           capture_output=True, text=True, timeout=45, check=False)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout[:1000])
        data = json.loads(p.stdout)
        self.assertEqual(data["schemaVersion"], "pgextwin-offline-major-inventory/v1")
        self.assertEqual(data["catalogCommitSha"],
                         "ebe65013b35c18f0d545b9d350ab63f7968fb92c")
        self.assertEqual(len(data["rows"]), 70)
        self.assertEqual(len(set((r["extension"], r["pgMajor"]) for r in data["rows"])), 70)
        self.assertEqual(len({r["extension"] for r in data["rows"]}), 14)
        self.assertEqual({r["pgMajor"] for r in data["rows"]},
                         {"14", "15", "16", "17", "18"})
        self.assertEqual(sum(r["formalP1"] == "ACCEPTED_RECORD_ONLY"
                             for r in data["rows"]), 65)
        self.assertEqual({(r["extension"], r["pgMajor"]) for r in data["rows"]
                          if r["formalP1"] == "DENY"},
                         {("plpgsql_check", str(pg)) for pg in range(14, 19)})
        self.assertEqual(data["historicalSourceAcceptedFromExistingLedger"], 40)
        self.assertFalse(data["archiveGenerationAuthorized"])
        self.assertFalse(data["publicationAuthorized"])
        self.assertFalse(data["distributionAuthorized"])
        self.assertEqual(len(data["majors"]), 5)
        for major in data["majors"]:
            self.assertFalse(major["complete"])
            self.assertFalse(major["distributionAuthorized"])
            self.assertEqual(major["proposedLocalZipName"],
                             f'pgextwin-offline-pg{major["pgMajor"]}-windows-x64.zip')
        print("P0_CLI_OUTPUT_70_ROWS_65_RECORD_ONLY_5_DENY_5_PG_INCOMPLETE_NO_PUBLISH=PASS")

    def test_cli_rejects_wrong_catalog_commit(self):
        p = subprocess.run([sys.executable, str(SCRIPT), "--catalog-commit",
                            "0" * 40], cwd=ROOT, capture_output=True,
                           text=True, timeout=45, check=False)
        self.assertEqual(p.returncode, 2)
        result = json.loads(p.stdout)
        self.assertEqual(result["decision"], "DENY")
        self.assertIs(result["distributionAuthorized"], False)


if __name__ == "__main__":
    unittest.main()
