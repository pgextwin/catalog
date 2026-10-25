"""Protected first-Release registry is dynamic but never self-authorizing."""
import json
import tempfile
import unittest
from pathlib import Path

from scripts.verified_release_record import (
    ALLOWED, FIRST_RELEASE, FIRST_RELEASE_SOURCES,
    INTAKE_ALLOWED, load_first_release_registry
)

ROOT = Path(__file__).resolve().parents[1]


class ProtectedInitialRegistryTests(unittest.TestCase):
    def setUp(self):
        self.original = json.loads((ROOT / "config/first-release-registry.json").read_text("utf-8"))

    def load(self, payload):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "registry.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return load_first_release_registry(path)

    def test_historical_and_third_wave_sources_unchanged(self):
        self.assertEqual(len(ALLOWED), 14)
        self.assertEqual(set(FIRST_RELEASE), set(FIRST_RELEASE_SOURCES))
        self.assertEqual(set(INTAKE_ALLOWED), set(ALLOWED) | set(FIRST_RELEASE_SOURCES))
        self.assertEqual(set(FIRST_RELEASE_SOURCES),
                         {"pgtap", "pg_variables", "pg_store_plans"})

    def test_future_name_is_data_driven_but_not_implicitly_admitted(self):
        future = {"name": "future_registered", "upstreamRepository": "safeorg/future_registered",
                  "displayName": "Future Registered", "description": "Fixture only",
                  "license": "PostgreSQL"}
        expanded = json.loads(json.dumps(self.original))
        expanded["entries"].append(future)
        expanded["entries"].sort(key=lambda row: row["name"])
        sources, meta = self.load(expanded)
        self.assertEqual(sources["future_registered"], "safeorg/future_registered")
        self.assertEqual(meta["future_registered"][0], "Future Registered")
        self.assertNotIn("future_registered", INTAKE_ALLOWED)

    def test_fail_closed_on_malformed_registry_and_source_changes(self):
        future = {"name": "future_registered", "upstreamRepository": "safeorg/future_registered",
                  "displayName": "Future Registered", "description": "Fixture only",
                  "license": "PostgreSQL"}
        rows = self.original["entries"]
        for bad in (
            {**self.original, "entries": list(reversed(rows))},
            {**self.original, "entries": rows + [rows[0]]},
            {**self.original, "entries": [*rows[:-1], {**rows[-1], "upstreamRepository": "evil/source"}]},
            {**self.original, "entries": sorted([*rows, {**future, "name": "../bad"}],
                                                   key=lambda row: row["name"])},
            {**self.original, "entries": sorted([*rows, {**future, "name": "pg_cron"}],
                                                   key=lambda row: row["name"])},
            {**self.original, "entries": sorted([*rows, {**future, "unexpected": True}],
                                                   key=lambda row: row["name"])},
            {**self.original, "schemaVersion": 2},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.load(bad)
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "duplicate.json"
            file.write_text('{"schemaVersion":1,"schemaVersion":1,"entries":[]}')
            with self.assertRaises(ValueError):
                load_first_release_registry(file)


if __name__ == "__main__":
    unittest.main()
