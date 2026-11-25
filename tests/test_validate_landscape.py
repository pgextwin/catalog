import copy
import importlib.util
import json
import shutil
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
        cls.impl = module.build_identities.project_landscape_v1(
            module.load(ROOT / "identities" / "pg_cron.json")
        )
        cls.candidate = module.build_identities.project_landscape_v1(
            module.load(ROOT / "identities" / "pg_partman.json")
        )
        cls.candidate["status"] = "candidate"
        cls.candidate.pop("pgextwinCatalogName", None)
        cls.candidate["candidateRationale"] = "Offline fixture candidate"
        cls.candidate["roadmap"] = {"decision": "reserve", "decisionDate": "2026-10-08", "rationale": "fixture"}
        cls.other = module.build_identities.project_landscape_v1(
            module.load(ROOT / "identities" / "postgis.json")
        )

    def assertValid(self, record):
        self.assertEqual([], list(self.validator.iter_errors(record)))

    def assertInvalid(self, record):
        self.assertNotEqual([], list(self.validator.iter_errors(record)))

    def test_valid_types(self):
        for record in [self.impl, self.candidate, self.other]:
            self.assertValid(record)

    def test_invalid_record_schema(self):
        cases = (
            ("not-planned reason missing", self.other, lambda r: r.pop("notPlannedReason")),
            ("not-planned sources missing", self.other, lambda r: r.update(windowsBinarySources=[])),
            ("bad source URL", self.other,
             lambda r: r["windowsBinarySources"][0].update(url="javascript:alert(1)")),
            ("candidate rationale missing", self.candidate, lambda r: r.pop("candidateRationale")),
            ("implemented reference missing", self.impl, lambda r: r.pop("pgextwinCatalogName")),
            ("invalid status", self.impl, lambda r: r.update(status="unsupported")),
            ("bad review date", self.impl, lambda r: r.update(lastReviewed="2026-02-31")),
        )
        for label, original, mutate in cases:
            with self.subTest(case=label):
                record = copy.deepcopy(original)
                mutate(record)
                self.assertInvalid(record)

    def test_valid_registry(self):
        self.assertEqual([], module.validate_landscape(ROOT))

    def test_valid_registry_without_legacy_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            shutil.copytree(ROOT / "identities", base / "identities")
            shutil.copytree(ROOT / "schema", base / "schema")
            self.assertEqual([], module.validate_landscape(base))

    def test_duplicate_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            shutil.copytree(ROOT / "schema", base / "schema")
            (base / "identities").mkdir()
            idx = {
                "schemaVersion": 3,
                "identitiesDir": "identities",
                "packagesDir": "packages",
                "extensions": ["a", "a"],
                "identities": [
                    {
                        "name": "a",
                        "path": "identities/a.json",
                        "intakeClass": "distributed",
                        "ledgerPath": "packages/a.json",
                    },
                    {
                        "name": "a",
                        "path": "identities/a.json",
                        "intakeClass": "distributed",
                        "ledgerPath": "packages/a.json",
                    },
                ],
            }
            (base / "identities" / "index.candidate.json").write_text(json.dumps(idx), encoding="utf-8")
            self.assertTrue(any("duplicate" in x for x in module.validate_landscape(base)))

    def test_step18_implemented_wave_history(self):
        plpgsql_identity = module.load(ROOT / "identities" / "plpgsql_check.json")
        plpgsql = module.build_identities.project_landscape_v1(plpgsql_identity)
        self.assertValid(plpgsql)
        self.assertEqual("implemented", plpgsql["status"])
        self.assertEqual("plpgsql_check", plpgsql["pgextwinCatalogName"])
        self.assertEqual(
            {"decision": "wave-2", "order": 1, "decisionDate": "2026-10-08"},
            {key: plpgsql["roadmap"][key] for key in ("decision", "order", "decisionDate")},
        )
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

    def test_future_wave_two_implementations_same_schema(self):
        for name in ("hypopg", "wal2json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                shutil.copytree(ROOT / "identities", base / "identities")
                shutil.copytree(ROOT / "schema", base / "schema")
                idx_path = base / "identities" / "index.candidate.json"
                index = json.loads(idx_path.read_text(encoding="utf-8"))
                if name not in index["extensions"]:
                    index["extensions"].append(name)
                    index["extensions"].sort()
                for entry in index["identities"]:
                    if entry["name"] == name:
                        entry["intakeClass"] = "distributed"
                        entry["ledgerPath"] = f"packages/{name}.json"
                idx_path.write_text(json.dumps(index), encoding="utf-8")

                path = base / "identities" / f"{name}.json"
                record = json.loads(path.read_text(encoding="utf-8"))
                record["intake"]["class"] = "distributed"
                record["intake"]["distributionAllowed"] = True
                record["research"].pop("status", None)
                record["research"].pop("candidateRationale", None)
                path.write_text(json.dumps(record), encoding="utf-8")
                self.assertEqual([], module.validate_landscape(base))

    def test_invalid_registry_record(self):
        cases = (
            ("bad Catalog repository reference", "pg_cron",
             lambda r: r["distribution"].update(repository="pgextwin/fake"),
             "invalid distribution catalog reference"),
            ("bad Catalog ledgerPath reference", "pg_cron",
             lambda r: r["distribution"].update(ledgerPath="packages/fake.json"),
             "invalid distribution catalog reference"),
            ("distributed identity disallows distribution", "pg_cron",
             lambda r: r["intake"].update(distributionAllowed=False),
             "invalid distribution catalog reference"),
            ("missing Wave 2 record", "wal2json",
             lambda r: r["research"].pop("roadmap"),
             "exactly three"),
            ("duplicate Wave 2 order", "hypopg",
             lambda r: r["research"]["roadmap"].update(order=1),
             "order"),
            ("missing roadmap rationale", "hypopg",
             lambda r: r["research"]["roadmap"].update(rationale=""),
             "rationale"),
            ("reserve has order", "pg_partman",
             lambda r: r["research"].update(roadmap={
                 "decision": "reserve", "decisionDate": "2026-10-08",
                 "rationale": "illegal", "order": 2,
             }), "roadmap"),
            ("not-planned has roadmap", "postgis",
             lambda r: r["research"].update(roadmap={
                 "decision": "research", "decisionDate": "2026-10-08", "rationale": "test",
             }), "roadmap"),
            ("bad decision date", "hypopg",
             lambda r: r["research"]["roadmap"].update(decisionDate="2026-02-31"),
             "decisionDate"),
            ("missing Wave 2 order", "hypopg",
             lambda r: r["research"]["roadmap"].pop("order"),
             "order"),
            ("missing candidate rationale", "http",
             lambda r: r["research"].pop("candidateRationale"),
             "candidate rationale"),
            ("missing not-planned reason", "postgis",
             lambda r: r["research"].pop("notPlannedReason"),
             "not-planned reason"),
            ("missing not-planned acquisition source", "postgis",
             lambda r: r["research"].update(windowsBinarySources=[]),
             "acquisition source"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            shutil.copytree(ROOT / "identities", base / "identities")
            shutil.copytree(ROOT / "schema", base / "schema")
            for label, name, mutate, fragment in cases:
                with self.subTest(case=label):
                    path = base / "identities" / f"{name}.json"
                    original = path.read_bytes()
                    record = json.loads(original)
                    mutate(record)
                    try:
                        path.write_text(json.dumps(record), encoding="utf-8")
                        errors = module.validate_landscape(base)
                        self.assertTrue(any(fragment in issue for issue in errors), errors)
                    finally:
                        path.write_bytes(original)

            idx_path = base / "identities" / "index.candidate.json"
            original_idx = idx_path.read_bytes()
            try:
                idx = json.loads(original_idx)
                idx["extensions"].remove("pg_cron")
                idx_path.write_text(json.dumps(idx), encoding="utf-8")
                errors = module.validate_landscape(base)
                self.assertTrue(any("invalid distribution catalog reference" in issue for issue in errors), errors)
            finally:
                idx_path.write_bytes(original_idx)


if __name__ == "__main__":
    unittest.main()
