import hashlib
import json
import os
import tempfile
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from scripts.cli_signed_feed import build_feed, canonical, OPTIONAL_SCHEMA, SCHEMA

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
        # Removing an index entry alone still leaves an inconsistent record inventory.
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

    def test_pg14_eol_preserves_historical_record_but_omits_it_from_signed_feed(self):
        config = self.root / "config" / "cli-feed-majors.json"
        config.write_text(json.dumps({"schemaVersion": 1,
                                      "postgresqlMajors": ["15", "16", "17", "18"]}))
        # Original Catalog retains PG14 as a published historical asset.
        historical = json.loads((self.root / "extensions" / "hypopg.json").read_text())
        self.assertIn("14", historical["postgresql"])
        feed = self.generate()
        self.assertEqual(feed["postgresqlMajors"], ["15", "16", "17", "18"])
        self.assertEqual(feed["zipCount"], 56)
        self.assertEqual(len(feed["releases"]), 14)
        self.assertEqual(
            [row["pgMajor"] for row in feed["releases"][0]["packages"]],
            ["15", "16", "17", "18"])
        self.assertFalse(feed["publicationAuthorized"])
        self.assertFalse(feed["extensionSignatureVerified"])

        record = self.root / "extensions" / "hypopg.json"
        for forbidden in ("19", "013", "0"):
            altered = json.loads(record.read_text())
            altered["postgresql"][forbidden] = altered["postgresql"]["18"]
            record.write_text(json.dumps(altered))
            with self.subTest(extra=forbidden), self.assertRaises(ValueError):
                self.generate()
            record.write_text(json.dumps(historical))

        # A missing or unpublished approved major is never excused by PG14.
        altered = json.loads(record.read_text())
        del altered["postgresql"]["18"]
        record.write_text(json.dumps(altered))
        with self.assertRaises(ValueError):
            self.generate()
        altered["postgresql"]["18"] = historical["postgresql"]["18"]
        altered["postgresql"]["18"]["available"] = False
        record.write_text(json.dumps(altered))
        with self.assertRaises(ValueError):
            self.generate()

    def test_stage_reject_candidate_or_missing_original_release(self):
        self.include_wave3("pgtap")
        self.assets["pgtap"]["release"]["draft"] = True
        with self.assertRaises(ValueError):
            self.generate()
        self.assets["pgtap"]["release"]["draft"] = False
        self.assets["pgtap"]["release"]["published_at"] = None
        with self.assertRaises(ValueError):
            self.generate()

    def test_optional_pg19_preserves_required_packages_and_uses_same_asset_checks(self):
        config = self.root / "config" / "cli-feed-majors.json"
        required = ["15", "16", "17", "18"]
        policy = {"schemaVersion": 1, "postgresqlMajors": required}
        config.write_text(json.dumps(policy))
        baseline = self.generate()
        for optional in ("18", "20", "019", 19, None):
            config.write_text(json.dumps({**policy, "optionalPostgresqlMajor": optional}))
            with self.subTest(optional=optional), self.assertRaisesRegex(ValueError, "Unsafe optional"):
                self.generate()

        config.write_text(json.dumps({**policy, "optionalPostgresqlMajor": "19"}))
        v1, v2 = build_feed(self.root, SHA, self.load)
        self.assertEqual(canonical(v1), canonical(baseline))
        self.assertIsNone(v2)
        unavailable = self.root / "extensions" / "hypopg.json"
        record = json.loads(unavailable.read_text())
        record["postgresql"]["19"] = {"available": False}
        unavailable.write_text(json.dumps(record))
        v1, v2 = build_feed(self.root, SHA, self.load)
        self.assertEqual(v1["schemaVersion"], SCHEMA)
        self.assertIsNone(v2)

        ready = self.root / "extensions" / "wal2json.json"
        record = json.loads(ready.read_text())
        pg18 = record["postgresql"]["18"]
        asset = pg18["asset"].replace("-pg18-", "-pg19-")
        url = pg18["downloadUrl"].replace("-pg18-", "-pg19-")
        record["postgresql"]["19"] = {**pg18, "asset": asset, "downloadUrl": url}
        ready.write_text(json.dumps(record))
        release = self.assets["wal2json"]["release"]
        with self.assertRaisesRegex(ValueError, "does not match public Release"):
            self.generate()
        original = {"id": 301, "name": asset, "state": "uploaded",
                    "browser_download_url": url, "digest": "sha256:" + D}
        release["assets"].append(original)

        v1, feed = build_feed(self.root, SHA, self.load)
        # The required-only feed still pins the exact Catalog bytes of this commit.
        for path in (unavailable, ready):
            baseline["catalogSha256"][f"extensions/{path.name}"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(canonical(v1), canonical(baseline))
        self.assertEqual(feed["schemaVersion"], OPTIONAL_SCHEMA)
        self.assertEqual(feed["catalogCommit"], v1["catalogCommit"])
        self.assertEqual(feed["catalogSha256"], v1["catalogSha256"])
        self.assertEqual(feed["postgresqlMajors"], required)
        self.assertEqual(feed["optionalPostgresqlMajor"], "19")
        self.assertEqual(feed["zipCount"], baseline["zipCount"] + 1)
        for old, new in zip(baseline["releases"], feed["releases"], strict=True):
            packages = new["packages"]
            self.assertEqual(old, {**new, "packages": packages[:len(required)]})
            self.assertEqual([p["pgMajor"] for p in packages[len(required):]],
                             ["19"] if new["extension"] == "wal2json" else [])
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/cli-signed-catalog-feed.yml").read_text()
        inventory = textwrap.dedent(workflow.split("<<'FEED_INVENTORY_PY'\n", 1)[1]
                                    .split("          FEED_INVENTORY_PY\n", 1)[0])
        artifact = self.root / "verified-catalog-feed"
        artifact.mkdir()

        def verify_as(stem, candidate):
            for path in artifact.iterdir():
                path.unlink()
            (artifact / f"{stem}.json").write_bytes(canonical(candidate))
            (artifact / f"{stem}.sigstore.json").write_text("{}")
            return subprocess.run([sys.executable, "-c", inventory, str(artifact), SHA],
                                  text=True, capture_output=True)

        for stem, candidate in (("catalog-latest", v1), ("catalog-latest-v2", feed)):
            verified = verify_as(stem, candidate)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(verified.stdout.strip(), stem)
        v2_calls = self.publish_commands(workflow, "catalog-latest-v2", ref_exists=False)
        self.assertIn(f"release edit catalog-feed-v2-{SHA} --repo pgextwin/catalog "
                      "--draft=false --latest=false --prerelease", v2_calls)
        self.assertTrue(any(" --draft --latest=false --prerelease " in call for call in v2_calls))
        self.assertTrue(v2_calls[-1].startswith("api --method POST repos/pgextwin/catalog/git/refs "
                                               "-f ref=refs/heads/catalog-feed-v2-current "))

        verify_as("catalog-latest", baseline)
        v1_calls = self.publish_commands(workflow, "catalog-latest", ref_exists=False)
        self.assertIn(f"release edit catalog-feed-{SHA} --repo pgextwin/catalog --draft=false --latest=true", v1_calls)
        self.assertFalse(any("--prerelease" in call or "force=false" in call or
                             "ref=refs/heads/" in call for call in v1_calls))
        resumed_calls = self.publish_commands(workflow, "catalog-latest", ref_exists=True)
        self.assertEqual(resumed_calls[-1], "api --method PATCH "
                         f"repos/pgextwin/catalog/git/refs/heads/catalog-feed-v2-current -f sha={SHA} -F force=false")

        self.assertNotEqual(verify_as("catalog-latest", feed).returncode, 0)
        self.assertNotEqual(verify_as("catalog-latest-v2", v1).returncode, 0)
        feed["releases"][0]["packages"].pop(0)
        feed["zipCount"] -= 1
        self.assertNotEqual(verify_as("catalog-latest-v2", feed).returncode, 0)

        original["digest"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(ValueError, "does not match public Release"):
            self.generate()
        original["digest"] = "sha256:" + D
        for major in required:
            row = record["postgresql"].pop(major)
            ready.write_text(json.dumps(record))
            with self.subTest(missing=major), self.assertRaisesRegex(ValueError, "major set"):
                self.generate()
            record["postgresql"][major] = row
        ready.write_text(json.dumps(record))
        row = next(a for a in release["assets"] if a["name"] == pg18["asset"])
        release["assets"].remove(row)
        with self.assertRaisesRegex(ValueError, "does not match public Release"):
            self.generate()

    def publish_commands(self, workflow, stem, *, ref_exists):
        code = textwrap.dedent(workflow.split(
            "      - name: Create-only draft -> rehash -> public metadata Release", 1
        )[1].split("        run: |\n", 1)[1])
        log = self.root / "gh.log"
        log.unlink(missing_ok=True)
        # Exercise the actual release-routing shell with local copies in place of GitHub.
        gh = '''
python() { "$TEST_PYTHON" "$@"; }
gh() {
  printf '%s\\n' "$*" >> "$RUNNER_TEMP/gh.log"
  case "$1 $2" in
    "release download")
      cp "$RUNNER_TEMP"/verified-catalog-feed/* "$RUNNER_TEMP/feed-draft-audit"
      ;;
    "api repos/pgextwin/catalog/git/matching-refs/heads/catalog-feed-v2-current")
      printf '%s\\n' "$DISCOVERY_REFS"
      ;;
  esac
}
'''
        refs = [{"ref": "refs/heads/catalog-feed-v2-current"}] if ref_exists else []
        result = subprocess.run(["bash", "-c", gh + code], capture_output=True, text=True,
                                env={**os.environ, "RUNNER_TEMP": str(self.root), "SOURCE": SHA,
                                     "STEM": stem, "DISCOVERY_REFS": json.dumps(refs),
                                     "TEST_PYTHON": sys.executable})
        self.assertEqual(result.returncode, 0, result.stderr)
        return log.read_text().splitlines()

    def test_retired_extension_removed_from_authorized_roster(self):
        index = self.root / "index.json"
        for keep in (NAMES[1:], ["pg_cron"]):
            with self.subTest(count=len(keep)):
                for record in (self.root / "extensions").glob("*.json"):
                    if record.stem not in keep:
                        record.unlink()
                index.write_text(json.dumps({"schemaVersion": 2, "extensions": keep}))
                feed = self.generate()
                self.assertEqual(feed["extensionCount"], len(keep))
                self.assertEqual(feed["zipCount"], len(keep) * 5)
                self.assertEqual([r["extension"] for r in feed["releases"]], keep)
                self.assertEqual(set(feed["catalogSha256"]),
                                 {"index.json"} | {"extensions/" + n + ".json" for n in keep})
                self.assertFalse(feed["extensionSignatureVerified"])
                self.assertFalse(feed["publicationAuthorized"])
                self.assertFalse(feed["installAuthorized"])

    def test_roster_maximum_count_and_identifier_length(self):
        additions = ["future_%03d" % i for i in range(113)] + ["x" * 64]
        self.include_wave3(*additions)
        feed = self.generate()
        self.assertEqual(feed["extensionCount"], 128)
        self.assertEqual(feed["zipCount"], 128 * 5)
        self.assertEqual(len(feed["catalogSha256"]), 129)

    def test_roster_resource_identifier_and_order_bounds(self):
        index = self.root / "index.json"
        for names in ([], ["x%03d" % i for i in range(129)], NAMES[::-1],
                      NAMES + [NAMES[-1]], ["../bad"], ["Upper"], ["x" * 65], [1]):
            with self.subTest(names=names):
                index.write_text(json.dumps({"schemaVersion": 2, "extensions": names}))
                with self.assertRaises(ValueError):
                    self.generate()

    def test_stage_reject_index_record_inventory_mismatch(self):
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
        return build_feed(self.root, SHA, self.load)[0]

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
        workflows = Path(__file__).resolve().parents[1] / ".github" / "workflows"
        for name in ("validate.yml", "cli-candidate.yml"):
            with self.subTest(workflow=name):
                workflow = (workflows / name).read_text(encoding="utf-8")
                self.assertIn("$expectedCount -lt 1 -or $expectedCount -gt 128", workflow)
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
            feed.update(postgresqlMajors=["15", "16", "17", "18"],
                        optionalPostgresqlMajor="19", zipCount=73)
            source.write_text(json.dumps(feed))
            subprocess.run([sys.executable, "-c", code, str(source), str(notes)],
                           check=True, capture_output=True)
            self.assertIn("PostgreSQL 19 is available for 1 of these extensions.", notes.read_text())



if __name__ == "__main__":
    unittest.main()
