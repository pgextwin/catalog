"""Protected distributed intake registry is derived from identities/ and never self-authorizing."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.verified_release_record import (
    ALLOWED, FIRST_RELEASE, FIRST_RELEASE_SOURCES,
    INTAKE_ALLOWED, SEALED_FIRST_RELEASE_UPSTREAM, load_identities_intake,
)

ROOT = Path(__file__).resolve().parents[1]
RESEARCH_ONLY = {
    "http", "oracle_fdw", "pg_sphere", "pgroonga",
    "pgrouting", "pgvector", "postgis", "timescaledb",
}


class ProtectedInitialRegistryTests(unittest.TestCase):
    def _copy_identities(self, dest: Path) -> Path:
        target = dest / "identities"
        shutil.copytree(ROOT / "identities", target)
        return target

    def test_historical_and_third_wave_sources_unchanged(self):
        self.assertEqual(len(ALLOWED), 14)
        self.assertEqual(len(FIRST_RELEASE_SOURCES), 12)
        self.assertEqual(set(FIRST_RELEASE), set(FIRST_RELEASE_SOURCES))
        self.assertEqual(set(INTAKE_ALLOWED), set(ALLOWED) | set(FIRST_RELEASE_SOURCES))
        self.assertEqual(set(INTAKE_ALLOWED) & RESEARCH_ONLY, set())
        for name, upstream in {
            "pg_store_plans": "ossc-db/pg_store_plans",
            "pg_variables": "postgrespro/pg_variables",
            "pgtap": "theory/pgtap",
        }.items():
            self.assertEqual(FIRST_RELEASE_SOURCES[name], upstream)
            self.assertEqual(SEALED_FIRST_RELEASE_UPSTREAM[name], upstream)

    def test_future_name_is_data_driven_but_not_implicitly_admitted(self):
        future = {
            "schemaVersion": 1,
            "name": "future_registered",
            "displayName": "Future Registered",
            "upstreamRepository": "safeorg/future_registered",
            "description": "Fixture only",
            "intake": {
                "class": "distributed",
                "distributionAllowed": True,
                "registrationSource": "first-release-registry",
                "expectedUpstreamRepository": "safeorg/future_registered",
                "sealedUpstream": False,
            },
            "distribution": {
                "repository": "pgextwin/future_registered",
                "license": "PostgreSQL",
                "ledgerPath": "packages/future_registered.json",
            },
            "research": {
                "lastReviewed": "2026-11-25",
                "evidenceUrls": ["https://github.com/safeorg/future_registered"],
                "windowsBinarySources": [],
            },
        }
        with tempfile.TemporaryDirectory() as temp:
            ident_dir = self._copy_identities(Path(temp))
            (ident_dir / "future_registered.json").write_text(json.dumps(future), encoding="utf-8")
            hist, first_sources, first_meta, identities = load_identities_intake(ident_dir)
        self.assertEqual(hist, ALLOWED)
        self.assertEqual(first_sources["future_registered"], "safeorg/future_registered")
        self.assertEqual(first_meta["future_registered"], ("Future Registered", "Fixture only", "PostgreSQL"))
        self.assertIn("future_registered", identities)
        self.assertNotIn("future_registered", INTAKE_ALLOWED)

    def test_fail_closed_on_malformed_identities_and_intake_tampering(self):
        mutations = [
            ("pgtap.json", lambda d: d["intake"].update(expectedUpstreamRepository="evil/source")),
            ("pgtap.json", lambda d: d["intake"].update(sealedUpstream=False)),
            ("pgtap.json", lambda d: d.update(upstreamRepository="evil/source")),
            ("hypopg.json", lambda d: d["intake"].update(sealedUpstream=False)),
            ("hypopg.json", lambda d: d["intake"].update(registrationSource="first-release-registry")),
            ("http.json", lambda d: d["intake"].update(distributionAllowed=True)),
            ("http.json", lambda d: d.update(distribution={
                "repository": "pgextwin/http", "license": "MIT", "ledgerPath": "packages/http.json"})),
            ("odbc_fdw.json", lambda d: d["intake"].update({"class": "other"})),
            ("odbc_fdw.json", lambda d: d.update(name="other_name")),
            ("odbc_fdw.json", lambda d: d.update(schemaVersion=2)),
            ("odbc_fdw.json", lambda d: d.update(extraField=True)),
        ]
        for filename, mutator in mutations:
            with self.subTest(filename=filename, mutator=mutator), tempfile.TemporaryDirectory() as temp:
                ident_dir = self._copy_identities(Path(temp))
                target = ident_dir / filename
                doc = json.loads(target.read_text("utf-8"))
                mutator(doc)
                target.write_text(json.dumps(doc), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_identities_intake(ident_dir)

        with tempfile.TemporaryDirectory() as temp:
            ident_dir = self._copy_identities(Path(temp))
            (ident_dir / "hypopg.json").unlink()
            with self.assertRaises(ValueError):
                load_identities_intake(ident_dir)

        with tempfile.TemporaryDirectory() as temp:
            ident_dir = self._copy_identities(Path(temp))
            (ident_dir / "BadName.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_identities_intake(ident_dir)

        with tempfile.TemporaryDirectory() as temp:
            ident_dir = self._copy_identities(Path(temp))
            raw = (ident_dir / "odbc_fdw.json").read_text("utf-8")
            (ident_dir / "odbc_fdw.json").write_text(
                raw.replace('"schemaVersion": 1', '"schemaVersion": 1, "schemaVersion": 1'),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_identities_intake(ident_dir)


if __name__ == "__main__":
    unittest.main()
