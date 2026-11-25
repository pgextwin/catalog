import copy
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from scripts import build_identities

ROOT = Path(__file__).resolve().parents[1]


class BuildIdentitiesTests(unittest.TestCase):
    def _copy_sources(self, dest: Path, *, include_identities: bool = False) -> Path:
        for directory in ("extensions", "packages", "landscape", "schema"):
            shutil.copytree(ROOT / directory, dest / directory)
        if include_identities:
            shutil.copytree(ROOT / "identities", dest / "identities")
        (dest / "config").mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "config" / "first-release-registry.json", dest / "config" / "first-release-registry.json")
        shutil.copy2(ROOT / "index.json", dest / "index.json")
        return dest

    def _mutate_json(self, path: Path, mutator) -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        mutator(data)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def test_committed_identities_pass_check_and_invariants(self):
        count, changed = build_identities.sync_identities(ROOT, check=True)
        self.assertEqual(34, count)
        self.assertEqual(0, changed)

        identities_dir = ROOT / "identities"
        identity_files = sorted(
            p for p in identities_dir.glob("*.json") if p.name != "index.candidate.json"
        )
        self.assertEqual(34, len(identity_files))

        records = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in identity_files}
        distributed = [r for r in records.values() if r["intake"]["class"] == "distributed"]
        research_only = [r for r in records.values() if r["intake"]["class"] == "research-only"]
        self.assertEqual(26, len(distributed))
        self.assertEqual(8, len(research_only))

        historical = [r for r in distributed if r["intake"]["registrationSource"] == "historical-core"]
        first_release = [r for r in distributed if r["intake"]["registrationSource"] == "first-release-registry"]
        self.assertEqual(14, len(historical))
        self.assertEqual(12, len(first_release))
        self.assertEqual(17, sum(1 for r in distributed if r["intake"]["sealedUpstream"] is True))
        self.assertEqual(9, sum(1 for r in distributed if r["intake"]["sealedUpstream"] is False))

        self.assertEqual(
            {
                "orafce", "pg_bigm", "pg_cron", "pg_hint_plan", "pg_ivm", "pg_partman",
                "pg_qualstats", "pg_repack", "pg_stat_monitor", "pgaudit", "plpgsql_check", "set_user",
            },
            {r["name"] for r in records.values() if "descriptionOverride" in r["research"]},
        )
        self.assertEqual(
            {"http", "hypopg", "pg_sphere", "pgaudit", "pgroonga", "pgrouting", "pgtap", "postgis", "timescaledb"},
            {r["name"] for r in records.values() if "displayName" in r},
        )
        self.assertEqual(2, sum(1 for r in research_only if r["research"]["status"] == "candidate"))
        self.assertEqual(6, sum(1 for r in research_only if r["research"]["status"] == "not-planned"))

        candidate_index = json.loads((identities_dir / "index.candidate.json").read_text(encoding="utf-8"))
        self.assertEqual(3, candidate_index["schemaVersion"])
        self.assertEqual(26, len(candidate_index["extensions"]))
        self.assertEqual(34, len(candidate_index["identities"]))
        self.assertEqual(set(), set(candidate_index["extensions"]) & {r["name"] for r in research_only})

    def test_generator_is_deterministic_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._copy_sources(Path(tmp))
            count1, changed1 = build_identities.sync_identities(root, check=False)
            self.assertEqual((34, 35), (count1, changed1))

            snapshot1 = {
                p.name: p.read_bytes()
                for p in sorted((root / "identities").iterdir())
            }
            count2, changed2 = build_identities.sync_identities(root, check=False)
            self.assertEqual((34, 0), (count2, changed2))

            snapshot2 = {
                p.name: p.read_bytes()
                for p in sorted((root / "identities").iterdir())
            }
            self.assertEqual(snapshot1, snapshot2)

            check_count, check_changed = build_identities.sync_identities(root, check=True)
            self.assertEqual((34, 0), (check_count, check_changed))

    def test_refuses_wrong_distributed_or_total_counts_or_unknown_landscape_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._copy_sources(Path(tmp))
            self._mutate_json(root / "index.json", lambda doc: doc["extensions"].pop())
            with self.assertRaisesRegex(ValueError, "extensions/ inventory differs|Expected 26"):
                build_identities.sync_identities(root)

        with tempfile.TemporaryDirectory() as tmp:
            root = self._copy_sources(Path(tmp))
            (root / "extensions" / "wal2json.json").unlink()
            (root / "packages" / "wal2json.json").unlink()
            self._mutate_json(root / "index.json", lambda doc: doc["extensions"].remove("wal2json"))
            with self.assertRaisesRegex(ValueError, "expected 26 distributed IDs"):
                build_identities.sync_identities(root)

        with tempfile.TemporaryDirectory() as tmp:
            root = self._copy_sources(Path(tmp))
            (root / "landscape" / "extensions" / "http.json").unlink()
            self._mutate_json(root / "landscape" / "index.json", lambda doc: doc["extensions"].remove("http"))
            with self.assertRaisesRegex(ValueError, "expected 34 total IDs"):
                build_identities.sync_identities(root)

        with tempfile.TemporaryDirectory() as tmp:
            root = self._copy_sources(Path(tmp))
            unknown = json.loads((root / "landscape" / "extensions" / "postgis.json").read_text(encoding="utf-8"))
            unknown["name"] = "unknown_ext"
            (root / "landscape" / "extensions" / "unknown_ext.json").write_text(
                json.dumps(unknown), encoding="utf-8"
            )
            self._mutate_json(root / "landscape" / "index.json", lambda doc: doc["extensions"].append("unknown_ext"))
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "build_identities.py"), "--root", str(root)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("neither distributed nor known research-only", result.stderr)

    def test_refuses_research_id_in_distribution_or_extra_file_in_identities(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._copy_sources(Path(tmp))
            shutil.copy2(root / "extensions" / "hypopg.json", root / "extensions" / "http.json")
            shutil.copy2(root / "packages" / "hypopg.json", root / "packages" / "http.json")
            self._mutate_json(root / "index.json", lambda doc: doc["extensions"].sort() or None)
            self._mutate_json(
                root / "index.json",
                lambda doc: doc.update(extensions=sorted([*doc["extensions"], "http"])),
            )
            with self.assertRaisesRegex(ValueError, "expected 26 distributed IDs"):
                build_identities.sync_identities(root)

        with tempfile.TemporaryDirectory() as tmp:
            root = self._copy_sources(Path(tmp), include_identities=True)
            (root / "identities" / "extra.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unexpected entry"):
                build_identities.sync_identities(root, check=True)

    def test_identity_and_index_v3_schemas_enforce_class_boundaries(self):
        identity_schema = json.loads((ROOT / "schema" / "identity.schema.json").read_text(encoding="utf-8"))
        index_v3_schema = json.loads((ROOT / "schema" / "index-v3.schema.json").read_text(encoding="utf-8"))
        id_val = Draft202012Validator(identity_schema, format_checker=FormatChecker())
        idx_val = Draft202012Validator(index_v3_schema, format_checker=FormatChecker())

        hypopg = json.loads((ROOT / "identities" / "hypopg.json").read_text(encoding="utf-8"))
        postgis = json.loads((ROOT / "identities" / "postgis.json").read_text(encoding="utf-8"))
        index_v3 = json.loads((ROOT / "identities" / "index.candidate.json").read_text(encoding="utf-8"))

        self.assertEqual([], list(id_val.iter_errors(hypopg)))
        self.assertEqual([], list(id_val.iter_errors(postgis)))
        self.assertEqual([], list(idx_val.iter_errors(index_v3)))

        bad_res_with_dist = copy.deepcopy(postgis)
        bad_res_with_dist["distribution"] = copy.deepcopy(hypopg["distribution"])
        self.assertTrue(list(id_val.iter_errors(bad_res_with_dist)))

        bad_dist_with_status = copy.deepcopy(hypopg)
        bad_dist_with_status["research"]["status"] = "implemented"
        self.assertTrue(list(id_val.iter_errors(bad_dist_with_status)))

        bad_dist_no_dist = copy.deepcopy(hypopg)
        bad_dist_no_dist.pop("distribution")
        self.assertTrue(list(id_val.iter_errors(bad_dist_no_dist)))

        bad_res_override = copy.deepcopy(postgis)
        bad_res_override["research"]["descriptionOverride"] = "Override"
        self.assertTrue(list(id_val.iter_errors(bad_res_override)))

        bad_idx_res_ledger = copy.deepcopy(index_v3)
        bad_idx_res_ledger["identities"][0]["ledgerPath"] = "packages/http.json"
        self.assertTrue(list(idx_val.iter_errors(bad_idx_res_ledger)))

        bad_idx_dist_no_ledger = copy.deepcopy(index_v3)
        bad_idx_dist_no_ledger["identities"][1].pop("ledgerPath")
        self.assertTrue(list(idx_val.iter_errors(bad_idx_dist_no_ledger)))


if __name__ == "__main__":
    unittest.main()
