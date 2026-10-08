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

    def test_step18_implemented_wave_history(self):
        plpgsql = module.load(ROOT / "landscape" / "extensions" / "plpgsql_check.json")
        self.assertValid(plpgsql)
        self.assertEqual("implemented", plpgsql["status"])
        self.assertEqual("plpgsql_check", plpgsql["pgextwinCatalogName"])
        self.assertEqual({"decision": "wave-2", "order": 1, "decisionDate": "2026-10-08"}, {key: plpgsql["roadmap"][key] for key in ("decision", "order", "decisionDate")})
        for choice in ("reserve", "research"):
            bad = copy.deepcopy(plpgsql)
            bad["roadmap"]["decision"] = choice
            bad["roadmap"].pop("order")
            self.assertInvalid(bad)
        bad = copy.deepcopy(plpgsql)
        bad.pop("pgextwinCatalogName")
        self.assertInvalid(bad)
        bad = copy.deepcopy(self.other)
        bad["roadmap"] = plpgsql["roadmap"]
        self.assertInvalid(bad)

    def test_step18_registry_counts_and_historical_compatibility(self):
        records = [module.load(p) for p in (ROOT / "landscape" / "extensions").glob("*.json")]
        statuses = {status: sum(r["status"] == status for r in records) for status in ("implemented", "candidate", "not-planned")}
        self.assertEqual(20, len(records))
        self.assertEqual({"implemented": 9, "candidate": 5, "not-planned": 6}, statuses)
        byname = {r["name"]: r for r in records}
        for name in module.INITIAL_EIGHT:
            self.assertEqual("implemented", byname[name]["status"])
        for name, order in (("hypopg",2),("wal2json",3)):
            self.assertEqual("candidate", byname[name]["status"])
            self.assertEqual(order, byname[name]["roadmap"]["order"])
            self.assertEqual("2026-10-08", byname[name]["roadmap"]["decisionDate"])
        for record in records:
            if record["status"] == "not-planned":
                self.assertTrue(record["windowsBinarySources"])
        catalog_index = module.load(ROOT / "index.json")["extensions"]
        self.assertEqual(set(catalog_index), {r["name"] for r in records if r["status"] == "implemented"})
        self.assertTrue(all(name not in catalog_index for name in ("hypopg", "wal2json")))

    def test_future_wave_two_implementations_same_schema(self):
        import shutil
        for name in ("hypopg", "wal2json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                shutil.copytree(ROOT / "landscape", base / "landscape")
                shutil.copytree(ROOT / "schema", base / "schema")
                index = module.load(ROOT / "index.json")
                index["extensions"].append(name)
                (base / "index.json").write_text(json.dumps(index))
                path = base / "landscape" / "extensions" / (name + ".json")
                record = json.loads(path.read_text())
                record["status"] = "implemented"
                record["pgextwinCatalogName"] = name
                record.pop("candidateRationale")
                path.write_text(json.dumps(record))
                self.assertEqual([], module.validate_landscape(base))

    def test_three_wave_two_orders(self):
        records = [module.load(p) for p in (ROOT / "landscape" / "extensions").glob("*.json")]
        wave = [x for x in records if x.get("roadmap", {}).get("decision") == "wave-2"]
        self.assertEqual([1, 2, 3], sorted(x["roadmap"]["order"] for x in wave))
        self.assertEqual(3, len(wave))
    def test_missing_all_wave_orders_rejected(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            shutil.copytree(ROOT / "landscape", base / "landscape")
            shutil.copytree(ROOT / "schema", base / "schema")
            shutil.copy(ROOT / "index.json", base / "index.json")
            for name in ("hypopg", "plpgsql_check", "wal2json"):
                path = base / "landscape" / "extensions" / (name + ".json")
                record = json.loads(path.read_text())
                record.pop("roadmap")
                path.write_text(json.dumps(record))
            errors = module.validate_landscape(base)
            self.assertTrue(any("exactly three" in issue for issue in errors), errors)
    def test_one_wave_record_missing_rejected(self):
        self.assertRegistryMutationRejected("wal2json",lambda x: x.pop("roadmap"), "exactly three")
    def test_duplicate_wave_order_rejected(self):
        self.assertRegistryMutationRejected("hypopg", lambda x: x["roadmap"].update(order=1), "order")
    def test_missing_roadmap_rationale_rejected(self):
        self.assertRegistryMutationRejected("hypopg", lambda x: x["roadmap"].update(rationale=""), "rationale")
    def test_reserve_cannot_have_order(self):
        self.assertRegistryMutationRejected("pg_partman", lambda x: x["roadmap"].update(order=2), "order")
    def test_not_planned_roadmap_rejected(self):
        self.assertRegistryMutationRejected("postgis", lambda x: x.update(roadmap={"decision":"research","decisionDate":"2026-10-08","rationale":"test"}), "roadmap")
    def test_bad_decision_date_rejected(self):
        self.assertRegistryMutationRejected("hypopg", lambda x: x["roadmap"].update(decisionDate="2026-02-31"), "decisionDate")
    def test_missing_wave_order_rejected(self):
        self.assertRegistryMutationRejected("hypopg", lambda x: x["roadmap"].pop("order"), "order")
    def assertRegistryMutationRejected(self, name, mutate, fragment):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            shutil.copytree(ROOT / "landscape", base / "landscape")
            shutil.copytree(ROOT / "schema", base / "schema")
            shutil.copy(ROOT / "index.json", base / "index.json")
            path = base / "landscape" / "extensions" / (name + ".json")
            record = json.loads(path.read_text())
            mutate(record)
            path.write_text(json.dumps(record))
            errors = module.validate_landscape(base)
            self.assertTrue(any(fragment in issue for issue in errors), errors)

if __name__ == "__main__":
    unittest.main()
