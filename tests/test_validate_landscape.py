import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("landscape_validator", ROOT / "scripts" / "validate_landscape.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class LandscapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = module.load(ROOT / "schema" / "landscape-extension.schema.json")
        cls.validator = module.Draft202012Validator(cls.schema, format_checker=module.FormatChecker())
        cls.impl = module.load(ROOT / "landscape" / "extensions" / "pg_cron.json")
        cls.candidate = module.load(ROOT / "landscape" / "extensions" / "wal2json.json")
        cls.other = module.load(ROOT / "landscape" / "extensions" / "postgis.json")
    def assertValid(self, record):
        self.assertEqual([], list(self.validator.iter_errors(record)))
    def assertInvalid(self, record):
        self.assertNotEqual([], list(self.validator.iter_errors(record)))
    def test_valid_types(self):
        for record in [self.impl, self.candidate, self.other]:
            self.assertValid(record)
    def test_not_planned_reason_required(self):
        record = copy.deepcopy(self.other); record.pop("notPlannedReason"); self.assertInvalid(record)
    def test_not_planned_source_required(self):
        record = copy.deepcopy(self.other); record["windowsBinarySources"] = []; self.assertInvalid(record)
    def test_bad_source_url(self):
        record = copy.deepcopy(self.other); record["windowsBinarySources"][0]["url"] = "javascript:alert(1)"; self.assertInvalid(record)
    def test_candidate_rationale_required(self):
        record = copy.deepcopy(self.candidate); record.pop("candidateRationale"); self.assertInvalid(record)
    def test_implemented_catalog_reference_required(self):
        record = copy.deepcopy(self.impl); record.pop("pgextwinCatalogName"); self.assertInvalid(record)
    def test_invalid_status(self):
        record = copy.deepcopy(self.impl); record["status"] = "unsupported"; self.assertInvalid(record)
    def test_last_reviewed_date(self):
        record = copy.deepcopy(self.impl); record["lastReviewed"] = "2026-02-31"; self.assertInvalid(record)
    def test_valid_registry(self):
        self.assertEqual([], module.validate_landscape(ROOT))
    def test_duplicate_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "landscape").mkdir()
            idx = {"schemaVersion":1,"extensions":["a","a"]}
            (base / "landscape" / "index.json").write_text(json.dumps(idx))
            (base / "schema").mkdir()
            (base / "schema" / "landscape-extension.schema.json").write_text(json.dumps(self.schema))
            (base / "index.json").write_text(json.dumps({"extensions":[]}))
            (base / "landscape" / "extensions").mkdir()
            self.assertTrue(any("duplicate" in x for x in module.validate_landscape(base)))
    def test_invalid_catalog_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            import shutil
            shutil.copytree(ROOT / "landscape", base / "landscape")
            shutil.copytree(ROOT / "schema", base / "schema")
            shutil.copy(ROOT / "index.json", base / "index.json")
            record_path = base / "landscape" / "extensions" / "pg_cron.json"
            record = json.loads(record_path.read_text())
            record["pgextwinCatalogName"] = "fake"
            record_path.write_text(json.dumps(record))
            self.assertTrue(any("invalid distribution catalog reference" in x for x in module.validate_landscape(base)))
if __name__ == "__main__":
    unittest.main()
