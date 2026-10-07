import copy
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_catalog.py"

spec = importlib.util.spec_from_file_location("validate_catalog", MODULE_PATH)
validate_catalog = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validate_catalog
spec.loader.exec_module(validate_catalog)


class CatalogV2ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = validate_catalog.load_json(
            ROOT / "schema" / "extension.schema.json"
        )
        cls.valid = validate_catalog.load_json(
            ROOT / "extensions" / "pg_cron.json"
        )

    def errors_for(self, record):
        errors = validate_catalog.schema_errors(
            self.schema, record, "fixture"
        )
        errors.extend(
            validate_catalog.validate_record_semantics(record["name"], record)
        )
        return errors

    def assert_has_error(self, record, needle):
        errors = self.errors_for(record)
        self.assertTrue(
            any(needle in error for error in errors),
            f"expected error containing {needle!r}; got:\n" + "\n".join(errors),
        )

    def test_valid_v2_record(self):
        self.assertEqual([], self.errors_for(copy.deepcopy(self.valid)))

    def test_available_missing_sha256(self):
        record = copy.deepcopy(self.valid)
        del record["postgresql"]["18"]["sha256"]
        self.assert_has_error(record, "sha256")

    def test_download_url_mismatch(self):
        record = copy.deepcopy(self.valid)
        record["postgresql"]["18"]["downloadUrl"] = (
            "https://github.com/pgextwin/pg_cron/releases/download/"
            "wrong-tag/pg_cron-v1.6.8-pg18-windows-x64.zip"
        )
        self.assert_has_error(record, "downloadUrl must be")

    def test_invalid_sha256(self):
        record = copy.deepcopy(self.valid)
        record["postgresql"]["18"]["sha256"] = "not-a-sha"
        self.assert_has_error(record, "sha256")

    def test_invalid_capability_source_commit(self):
        record = copy.deepcopy(self.valid)
        record["capabilitiesSource"]["commit"] = "main"
        self.assert_has_error(record, "commit")

    def test_evidence_available_missing_asset(self):
        record = copy.deepcopy(self.valid)
        record["postgresql"]["18"]["evidence"]["sbom"] = {
            "available": True,
            "downloadUrl": (
                "https://github.com/pgextwin/pg_cron/releases/download/"
                "v1.6.8-windows.1/pg_cron-v1.6.8-pg18-windows-x64.spdx.json"
            ),
            "sha256": "0" * 64,
        }
        self.assert_has_error(record, "asset")

    def test_duplicate_functional_scenario(self):
        record = copy.deepcopy(self.valid)
        record["capabilities"]["functionalScenarios"].append(
            copy.deepcopy(record["capabilities"]["functionalScenarios"][0])
        )
        self.assert_has_error(record, "duplicate functional scenario")

    def test_forbidden_lifecycle_field(self):
        record = copy.deepcopy(self.valid)
        record["postgresql"]["18"]["eol"] = "2027-11-11"
        self.assert_has_error(record, "eol")

    def test_client_path_and_coverage_consistency(self):
        record = copy.deepcopy(self.valid)
        record["runtime"]["requirements"]["clientExecutable"] = {
            "required": True,
            "packagePaths": [],
        }
        record["capabilities"]["coverage"]["clientExecutable"] = "covered"
        self.assert_has_error(record, "client executable")

    def test_unavailable_evidence_cannot_have_artifact_fields(self):
        record = copy.deepcopy(self.valid)
        record["postgresql"]["18"]["evidence"]["vulnerabilityReport"] = {
            "available": False,
            "asset": "fictional.vulnerabilities.json",
        }
        self.assert_has_error(record, "unavailable evidence")


if __name__ == "__main__":
    unittest.main()
