import hashlib
import json
import tempfile
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from scripts.cli_signed_feed import build_feed, canonical, SCHEMA

NAMES = ["hypopg","orafce","pg_bigm","pg_cron","pg_hint_plan",
         "pg_ivm","pg_partman","pg_qualstats","pg_repack",
         "pg_stat_monitor","pgaudit","plpgsql_check","set_user","wal2json"]
SHA = "a" * 40
D = "b" * 64


class SignedFeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "extensions").mkdir()
        (self.root / "config").mkdir()
        (self.root / "config" / "cli-feed-majors.json").write_text(json.dumps(
            {"schemaVersion": 1, "postgresqlMajors": ["14", "15", "16", "17", "18"]}))
        (self.root / "index.json").write_text(json.dumps(
            {"schemaVersion": 2, "extensions": NAMES}), encoding="utf-8")
        self.assets = {}
        for name in NAMES:
            packages = {}
            for major in ("14", "15", "16", "17", "18"):
                asset = f"{name}-v1-pg{major}-windows-x64.zip"
                packages[major] = {
                    "available": True, "asset": asset, "sha256": D,
                    "downloadUrl": f"https://github.com/pgextwin/{name}/releases/download/v1/{asset}",
                }
            (self.root / "extensions" / (name + ".json")).write_text(json.dumps({
                "schemaVersion": 2, "name": name, "repository": "pgextwin/" + name,
                "architecture": "x64", "latest": {"releaseTag": "v1"},
                "postgresql": packages,
            }), encoding="utf-8")
            files = []
            for i, pg in enumerate(packages.values()):
                files.append({
                    "id": i + 100, "name": pg["asset"], "state": "uploaded",
                    "browser_download_url": pg["downloadUrl"], "digest": "sha256:" + D
                })
            files.append({
                "id": 300, "name": "SHA256SUMS.txt", "state": "uploaded",
                "browser_download_url": f"https://github.com/pgextwin/{name}/releases/download/v1/SHA256SUMS.txt",
                "digest": "sha256:" + ("c" * 64),
            })
            self.assets[name] = {
                "repo": {"id": 400, "full_name": "pgextwin/" + name},
                "release": {"id": 500, "tag_name": "v1", "draft": False,
                            "published_at": "2026-10-19T00:00:00Z", "assets": files}
            }

    def include_wave3(self, *additions):
        # Synthetic future verified Catalog intake, never real Releases.
        original = (self.root / "extensions" / "hypopg.json").read_text()
        for name in additions:
            (self.root / "extensions" / (name + ".json")).write_text(
                original.replace("hypopg", name), encoding="utf-8")
            self.assets[name] = json.loads(
                json.dumps(self.assets["hypopg"]).replace("hypopg", name))
        (self.root / "index.json").write_text(json.dumps(
            {"schemaVersion": 2, "extensions": sorted(NAMES + list(additions))}),
            encoding="utf-8")

    def test_stage_15_16_17_only_after_indexed_published_release(self):
        for additions in (("pgtap",),
                          ("pgtap", "pg_variables"),
                          ("pgtap", "pg_variables", "pg_store_plans")):
            with self.subTest(extensions=additions):
                self.include_wave3(*additions)
                feed = self.generate()
                self.assertEqual(feed["extensionCount"], 14 + len(additions))
                self.assertEqual(feed["zipCount"], 5 * (14 + len(additions)))
                self.assertFalse(feed["extensionSignatureVerified"])
                self.assertFalse(feed["publicationAuthorized"])
                self.assertFalse(feed["installAuthorized"])
                self.assertEqual(len(feed["catalogSha256"]), 15 + len(additions))
                self.assertEqual(len(feed["releases"]), 14 + len(additions))

    def test_eighteenth_registered_extension_requires_real_index_record_and_release(self):
        self.include_wave3("pgtap", "pg_variables", "pg_store_plans", "new_future")
        feed = self.generate()
        self.assertEqual(feed["extensionCount"], 18)
        self.assertEqual(feed["zipCount"], 90)
        self.assertEqual(len(feed["releases"]), 18)
        self.assertFalse(feed["publicationAuthorized"])
        self.assertFalse(feed["extensionSignatureVerified"])
        # The historic 14 cannot be dropped even if a new name is present.
        idx = self.root / "index.json"
        idx.write_text(json.dumps({"schemaVersion": 2,
                                   "extensions": sorted((set(NAMES + ["new_future"]) |
                                                         {"pgtap", "pg_variables", "pg_store_plans"}) -
                                                         {"pg_cron"})}))
        with self.assertRaises(ValueError):
            self.generate()

    def test_postgresql_cohort_is_declared_not_inferred_from_malicious_record(self):
        config = self.root / "config" / "cli-feed-majors.json"
        before = config.read_text()
        for values in ([], ["14", "16"], ["14", "14"], ["14", "33"],
                       ["014", "15"], ["14", 15], list(map(str, range(14, 27)))):
            with self.subTest(majors=values):
                config.write_text(json.dumps({"schemaVersion": 1, "postgresqlMajors": values}))
                with self.assertRaises(ValueError):
                    self.generate()
        config.write_text(before)
        # A protected policy change alone is insufficient: actual Catalog
        # records and public-release bytes must agree for every major.
        config.write_text(json.dumps({"schemaVersion": 1,
                                      "postgresqlMajors": ["15", "16", "17", "18", "19"]}))
        with self.assertRaises(ValueError):
            self.generate()
        config.write_text(before)

    def test_stage_reject_candidate_or_missing_original_release(self):
        self.include_wave3("pgtap")
        self.assets["pgtap"]["release"]["draft"] = True
        with self.assertRaises(ValueError):
            self.generate()
        self.assets["pgtap"]["release"]["draft"] = False
        self.assets["pgtap"]["release"]["published_at"] = None
        with self.assertRaises(ValueError):
            self.generate()

    def test_stage_reject_wrong_roster_and_partial_historical_fleet(self):
        self.include_wave3("pgtap")
        index = self.root / "index.json"
        original = json.loads(index.read_text())
        variants = [
            sorted((set(original["extensions"]) - {"hypopg"})),
            sorted((set(original["extensions"]) - {"hypopg"}) | {"pg_repack_extra"}),
            sorted(set(original["extensions"]) | {"unexpected_extension"}),
        ]
        for names in variants:
            with self.subTest(names=names):
                index.write_text(json.dumps({"schemaVersion": 2, "extensions": names}))
                with self.assertRaises(ValueError):
                    self.generate()
        index.write_text(json.dumps(original))
        (self.root / "extensions" / "unindexed.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.generate()

    def tearDown(self):
        self.tmp.cleanup()

    def load(self, repo, route):
        name = repo.split("/")[-1]
        return self.assets[name]["release" if route else "repo"]

    def generate(self):
        return build_feed(self.root, SHA, self.load)

    def test_all_70_signed_feed_claims_not_original_signatures(self):
        feed = self.generate()
        self.assertEqual(feed["schemaVersion"], SCHEMA)
        self.assertEqual(feed["extensionCount"], 14)
        self.assertEqual(feed["zipCount"], 70)
        self.assertFalse(feed["extensionSignatureVerified"])
        self.assertFalse(feed["publicationAuthorized"])
        self.assertFalse(feed["installAuthorized"])
        self.assertEqual(len(feed["catalogSha256"]), 15)
        self.assertEqual(sum(len(a["packages"]) for a in feed["releases"]), 70)
        self.assertEqual(feed["releases"][0]["releaseId"], 500)
        self.assertEqual(feed["releases"][0]["packages"][0]["assetId"], 100)
        raw = canonical(feed)
        self.assertEqual(raw, canonical(json.loads(raw)))
        self.assertEqual(hashlib.sha256(
            (self.root / "index.json").read_bytes()).hexdigest(),
            feed["catalogSha256"]["index.json"])

    def test_reject_missing_or_moved_release(self):
        for field, value in (("draft", True), ("tag_name", "candidate")):
            with self.subTest(field=field):
                old = self.assets["hypopg"]["release"][field]
                self.assets["hypopg"]["release"][field] = value
                with self.assertRaises(ValueError):
                    self.generate()
                self.assets["hypopg"]["release"][field] = old

    def test_reject_mutated_digests_and_ids(self):
        asset = self.assets["hypopg"]["release"]["assets"][0]
        for k, value in (("digest", "sha256:" + "0" * 64),
                         ("id", 0), ("state", "deleted"),
                         ("browser_download_url", "https://evil.example/redirect")):
            old = asset[k]
            asset[k] = value
            with self.subTest(k=k), self.assertRaises(ValueError):
                self.generate()
            asset[k] = old

    def test_failclosed_missing_major(self):
        p = self.root / "extensions" / "hypopg.json"
        data = json.loads(p.read_text())
        data["postgresql"]["18"]["available"] = False
        p.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            self.generate()

    def test_failclosed_bad_commit(self):
        with self.assertRaises(ValueError):
            build_feed(self.root, "main", self.load)

    def test_failclosed_duplicate_catalog_json(self):
        p = self.root / "extensions" / "hypopg.json"
        p.write_text('{"name":"hypopg","name":"hypopg"}')
        with self.assertRaises(ValueError):
            self.generate()


    def test_windows_cli_smoke_tracks_signed_feed_fleet_capacity(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertIn("$expectedCount -lt 14 -or $expectedCount -gt 128", workflow)
        self.assertNotIn("$expectedCount -gt 17", workflow)

    def test_actual_release_note_formatter_tracks_signed_cohort_and_denies_false_claims(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/cli-signed-catalog-feed.yml").read_text()
        code = textwrap.dedent(workflow.split("<<'FEED_NOTES_PY'\n", 1)[1].split("          FEED_NOTES_PY\n", 1)[0])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, notes = root / "feed.json", root / "notes.md"
            for count, majors in ((17, ["14", "15", "16", "17", "18"]),
                                  (17, ["15", "16", "17", "18"]),
                                  (18, ["14", "15", "16", "17", "18", "19"])):
                feed = {"extensionCount": count, "postgresqlMajors": majors,
                        "zipCount": count * len(majors), "extensionSignatureVerified": False,
                        "publicationAuthorized": False, "installAuthorized": False}
                source.write_text(json.dumps(feed))
                run = subprocess.run([sys.executable, "-c", code, str(source), str(notes)],
                                     text=True, capture_output=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                result = notes.read_text()
                self.assertIn(f"{count} extensions and {count * len(majors)} original ZIPs", result)
                self.assertIn("PostgreSQL majors " + ", ".join(majors), result)
                self.assertIn(f"元ZIP計{count * len(majors)}件", result)
                self.assertLess(result.index("## English"), result.index("## 日本語"))
                self.assertIn("INTEGRITY_ONLY", result)
            for change in ({"zipCount": 85}, {"publicationAuthorized": True},
                           {"postgresqlMajors": ["14", "16"]}):
                source.write_text(json.dumps({**feed, **change}))
                notes.unlink(missing_ok=True)
                run = subprocess.run([sys.executable, "-c", code, str(source), str(notes)],
                                     text=True, capture_output=True)
                self.assertNotEqual(run.returncode, 0)
                self.assertFalse(notes.exists())



if __name__ == "__main__":
    unittest.main()
