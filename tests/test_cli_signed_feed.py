import base64
import io
import json
import os
import tempfile
import subprocess
import sys
import textwrap
import unittest
from copy import deepcopy
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from scripts.cli_signed_feed import build_feed, canonical, get_catalog_record, get_repo_json, SCHEMA

NAMES = ["hypopg","orafce","pg_bigm","pg_cron","pg_hint_plan",
         "pg_ivm","pg_partman","pg_qualstats","pg_repack",
         "pg_stat_monitor","pgaudit","plpgsql_check","set_user","wal2json"]
SHA = "a" * 40
D = "b" * 64
ADMISSION = "d" * 40


def latest(entry):
    return next(r for r in entry["releases"] if r["releaseTag"] == entry["latestReleaseTag"])


def zip_count(feed):
    return sum(len(r["packages"]) for e in feed["extensions"] for r in e["releases"])


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
        self.admissions = {}
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
                "postgresql": packages, "upstream": {"version": "1.0"},
                "releaseInventory": {
                    "current": {"releaseTag": "v1", "licensesByMajor": {
                        major: {"name": "PostgreSQL",
                                "evidenceUrls": [f"https://github.com/pgextwin/{name}/blob/{SHA}/LICENSE"]}
                        for major in packages}},
                    "history": [],
                },
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
                self.assertEqual(len(feed["extensions"]), 14 + len(additions))
                self.assertEqual(zip_count(feed), 5 * (14 + len(additions)))
                self.assertFalse(feed["extensionSignatureVerified"])
                self.assertFalse(feed["publicationAuthorized"])
                self.assertFalse(feed["installAuthorized"])

    def test_eighteenth_registered_extension_requires_real_index_record_and_release(self):
        self.include_wave3("pgtap", "pg_variables", "pg_store_plans", "new_future")
        feed = self.generate()
        self.assertEqual(len(feed["extensions"]), 18)
        self.assertEqual(zip_count(feed), 90)
        self.assertEqual(len(feed["extensions"]), 18)
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
        self.assertEqual(zip_count(feed), 56)
        self.assertEqual(len(feed["extensions"]), 14)
        self.assertEqual(
            [row["pgMajor"] for row in latest(feed["extensions"][0])["packages"]],
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
        self.assertEqual(baseline["schemaVersion"], SCHEMA)
        self.assertNotIn("optionalPostgresqlMajor", baseline)
        for optional in ("18", "20", "019", 19, None):
            config.write_text(json.dumps({**policy, "optionalPostgresqlMajor": optional}))
            with self.subTest(optional=optional), self.assertRaisesRegex(ValueError, "Unsafe optional"):
                self.generate()

        config.write_text(json.dumps({**policy, "optionalPostgresqlMajor": "19"}))
        # Optional major configured but no record carries it: the single feed
        # stays required-only and omits the optional declaration entirely.
        feed = self.generate()
        self.assertEqual(canonical(feed), canonical(baseline))
        self.assertNotIn("optionalPostgresqlMajor", feed)
        unavailable = self.root / "extensions" / "hypopg.json"
        record = json.loads(unavailable.read_text())
        record["postgresql"]["19"] = {"available": False}
        unavailable.write_text(json.dumps(record))
        feed = self.generate()
        self.assertEqual(feed["schemaVersion"], SCHEMA)
        self.assertNotIn("optionalPostgresqlMajor", feed)

        ready = self.root / "extensions" / "wal2json.json"
        record = json.loads(ready.read_text())
        pg18 = record["postgresql"]["18"]
        asset = pg18["asset"].replace("-pg18-", "-pg19-")
        url = pg18["downloadUrl"].replace("-pg18-", "-pg19-")
        record["postgresql"]["19"] = {**pg18, "asset": asset, "downloadUrl": url}
        licenses = record["releaseInventory"]["current"]["licensesByMajor"]
        licenses["19"] = licenses["18"]
        ready.write_text(json.dumps(record))
        release = self.assets["wal2json"]["release"]
        with self.assertRaisesRegex(ValueError, "does not match public Release"):
            self.generate()
        original = {"id": 301, "name": asset, "state": "uploaded",
                    "browser_download_url": url, "digest": "sha256:" + D}
        release["assets"].append(original)

        feed = build_feed(self.root, SHA, self.load)
        self.assertEqual(feed["schemaVersion"], SCHEMA)
        self.assertEqual(feed["catalogCommit"], baseline["catalogCommit"])
        self.assertEqual(feed["postgresqlMajors"], required)
        self.assertEqual(feed["optionalPostgresqlMajor"], "19")
        self.assertEqual(zip_count(feed), zip_count(baseline) + 1)
        for old, new in zip(baseline["extensions"], feed["extensions"], strict=True):
            packages = latest(new)["packages"]
            self.assertEqual(latest(old), {**latest(new), "packages": packages[:len(required)]})
            self.assertEqual([p["pgMajor"] for p in packages[len(required):]],
                             ["19"] if new["extension"] == "wal2json" else [])
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/cli-signed-catalog-feed.yml").read_text()
        inventory = textwrap.dedent(workflow.split("<<'FEED_INVENTORY_PY'\n", 1)[1]
                                    .split("          FEED_INVENTORY_PY\n", 1)[0])
        inventory = compile(inventory, "FEED_INVENTORY_PY", "exec")
        artifact = self.root / "verified-catalog-feed"
        artifact.mkdir()

        def verify(candidate):
            for path in artifact.iterdir():
                path.unlink()
            (artifact / "catalog-latest.json").write_bytes(canonical(candidate))
            (artifact / "catalog-latest.sigstore.json").write_text("{}")
            output = io.StringIO()
            with patch.object(sys, "argv", ["-", str(artifact), SHA]), redirect_stdout(output):
                exec(inventory, {"__name__": "__main__"})
            return output.getvalue()

        for candidate in (feed, baseline):
            self.assertEqual(verify(candidate).strip(), "catalog-latest")

        calls = self.publish_commands(workflow)
        self.assertIn(f"api --method POST repos/pgextwin/catalog/git/refs "
                      f"-f ref=refs/tags/catalog-feed-{SHA} -f sha={SHA}", calls)
        self.assertTrue(any(call.startswith(f"release create catalog-feed-{SHA} ") and
                            " --draft --latest=false " in call for call in calls))
        self.assertIn(f"release edit catalog-feed-{SHA} --repo pgextwin/catalog "
                      "--draft=false --latest=true", calls)
        self.assertFalse(any("--prerelease" in call or "force=false" in call or
                             "catalog-feed-v2" in call or "matching-refs" in call or
                             "ref=refs/heads/" in call for call in calls))

        latest(feed["extensions"][0])["packages"].pop(0)
        with self.assertRaises(AssertionError):
            verify(feed)
        # A v1-shaped body is no longer a valid published feed.
        legacy = {**baseline, "schemaVersion": "pgextwin-signed-catalog-zip-feed/v1"}
        with self.assertRaises(AssertionError):
            verify(legacy)

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

    def publish_commands(self, workflow):
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
  esac
}
'''
        result = subprocess.run(["bash", "-c", gh + code], capture_output=True, text=True,
                                env={**os.environ, "RUNNER_TEMP": str(self.root), "SOURCE": SHA,
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
                self.assertEqual(len(feed["extensions"]), len(keep))
                self.assertEqual(zip_count(feed), len(keep) * 5)
                self.assertEqual([r["extension"] for r in feed["extensions"]], keep)
                self.assertFalse(feed["extensionSignatureVerified"])
                self.assertFalse(feed["publicationAuthorized"])
                self.assertFalse(feed["installAuthorized"])

    def test_roster_maximum_count_and_identifier_length(self):
        additions = ["future_%03d" % i for i in range(113)] + ["x" * 64]
        self.include_wave3(*additions)
        feed = self.generate()
        self.assertEqual(len(feed["extensions"]), 128)
        self.assertEqual(zip_count(feed), 128 * 5)

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
        files = self.assets[name]
        if route:
            return files.get(route, files["release"])
        return files["repo"]

    def generate(self):
        return build_feed(self.root, SHA, self.load, load_admission=self.load_admission)

    def load_admission(self, commit, name):
        return self.admissions[commit, name]

    def test_all_70_signed_feed_claims_not_original_signatures(self):
        feed = self.generate()
        self.assertEqual(feed["schemaVersion"], SCHEMA)
        self.assertEqual(len(feed["extensions"]), 14)
        self.assertEqual(zip_count(feed), 70)
        self.assertFalse(feed["extensionSignatureVerified"])
        self.assertFalse(feed["publicationAuthorized"])
        self.assertFalse(feed["installAuthorized"])
        self.assertNotIn("catalogSha256", feed)
        self.assertEqual(latest(feed["extensions"][0])["releaseId"], 500)
        self.assertEqual(latest(feed["extensions"][0])["packages"][0]["assetId"], 100)
        raw = canonical(feed)
        self.assertEqual(raw, canonical(json.loads(raw)))
        self.assertNotIn("downloadUrl", latest(feed["extensions"][0])["packages"][0])
        self.assertNotIn("checksumsAssetId", latest(feed["extensions"][0]))

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
        workflow = (workflows / "cli-candidate.yml").read_text(encoding="utf-8")
        self.assertIn("$expectedCount -lt 1 -or $expectedCount -gt 128", workflow)
        self.assertNotIn("$expectedCount -gt 17", workflow)
        self.assertEqual(workflow.count("dotnet publish "), 1)

    def add_history(self):
        path = self.root / "extensions/hypopg.json"
        data = json.loads(path.read_text())
        old_tag = "v0"
        old_asset = "hypopg-v0-pg15-windows-x64.zip"
        license_info = {"name": "PostgreSQL",
                        "evidenceUrls": [f"https://github.com/pgextwin/hypopg/blob/{'c' * 40}/LICENSE",
                                         f"https://github.com/pgextwin/hypopg/blob/{'c' * 40}/NOTICE"]}
        data["releaseInventory"]["history"] = [{
            "releaseTag": old_tag, "releaseId": 501, "admission": {"catalogCommit": ADMISSION},
            "packages": [{"pgMajor": "15", "version": "0.9", "asset": old_asset,
                          "assetId": 201, "sha256": D, "license": license_info}],
        }]
        path.write_text(json.dumps(data))
        self.admissions[ADMISSION, "hypopg"] = {
            "name": "hypopg", "repository": "pgextwin/hypopg", "latest": {"releaseTag": old_tag},
            "upstream": {"version": "0.8", "perPostgresql": {"15": {"version": "0.9"}}},
            "postgresql": {"15": {"available": True, "asset": old_asset, "sha256": D}},
            "releaseInventory": {"current": {"releaseTag": old_tag, "licensesByMajor": {
                "15": deepcopy(license_info)}}},
        }
        self.assets["hypopg"]["/releases/tags/v0"] = {
            "id": 501, "tag_name": old_tag, "draft": False, "published_at": "2026-08-01T00:00:00Z",
            "assets": [{"name": name, "id": ident, "digest": "sha256:" + D, "state": "uploaded",
                        "browser_download_url": f"https://github.com/pgextwin/hypopg/releases/download/v0/{name}"}
                       for name, ident in ((old_asset, 201), ("SHA256SUMS.txt", 202))],
        }
        return path, data

    def test_history_admission_can_be_revoked_and_tags_are_read_once(self):
        path, data = self.add_history()
        calls = []

        def load(repo, route):
            calls.append((repo, route))
            return self.load(repo, route)

        before = build_feed(self.root, SHA, load, load_admission=self.load_admission)
        extension = before["extensions"][0]
        self.assertEqual([r["releaseTag"] for r in extension["releases"]], ["v0", "v1"])
        self.assertEqual(extension["releases"][0], data["releaseInventory"]["history"][0])
        self.assertEqual(latest(extension)["admission"]["catalogCommit"], SHA)
        self.assertEqual(calls.count(("pgextwin/hypopg", "/releases/tags/v0")), 1)
        self.assertEqual(calls.count(("pgextwin/hypopg", "/releases/tags/v1")), 1)
        data["releaseInventory"]["history"].clear()
        path.write_text(json.dumps(data))
        calls.clear()
        after = build_feed(self.root, SHA, load, load_admission=self.load_admission)
        self.assertEqual([r["releaseTag"] for r in after["extensions"][0]["releases"]], ["v1"])
        self.assertNotIn(("pgextwin/hypopg", "/releases/tags/v0"), calls)

    def test_history_rejects_incomplete_evidence_wrong_ids_and_duplicate_version(self):
        path, data = self.add_history()
        snapshot = data["releaseInventory"]["history"][0]
        package = snapshot["packages"][0]
        admitted = self.admissions[ADMISSION, "hypopg"]["upstream"]["perPostgresql"]["15"]
        for target, field, invalid, expected in (
                (snapshot, "releaseId", 7, "Release ID"),
                (snapshot["admission"], "catalogCommit", "main", "admission"),
                (package, "assetId", 202, "public Release"),
                (package, "license", {"name": "PostgreSQL", "evidenceUrls": []}, "license evidence"),
                (package, "version", "1.0", "Catalog admission ZIP or version mismatch")):
            with self.subTest(field=field):
                original = target[field]
                target[field] = invalid
                path.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError, expected):
                    self.generate()
                target[field] = original
        package["version"] = admitted["version"] = "1.0"
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "duplicate Catalog package version"):
            self.generate()

    def test_history_rejects_sha_that_points_to_a_different_catalog_release(self):
        path, data = self.add_history()
        other_sha = "e" * 40
        self.admissions[other_sha, "hypopg"] = json.loads(path.read_text())
        data["releaseInventory"]["history"][0]["admission"]["catalogCommit"] = other_sha
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "admission does not match historical Release"):
            self.generate()

    def test_history_rejects_one_missing_license_evidence_url(self):
        path, data = self.add_history()
        data["releaseInventory"]["history"][0]["packages"][0]["license"]["evidenceUrls"].pop()
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "admission license evidence mismatch"):
            self.generate()

    def test_legacy_history_checks_zip_digest_without_version_specific_license_record(self):
        self.add_history()
        record = self.admissions[ADMISSION, "hypopg"]
        del record["releaseInventory"]
        self.assertEqual(zip_count(self.generate()), 71)
        record["postgresql"]["15"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "admission ZIP or version mismatch"):
            self.generate()

    def test_history_fails_closed_without_a_working_admission_loader(self):
        self.add_history()
        with self.assertRaisesRegex(ValueError, "admission loader required"):
            build_feed(self.root, SHA, self.load)
        self.admissions.clear()
        with self.assertRaisesRegex(ValueError, "unable to load Catalog admission"):
            self.generate()

    def test_history_does_not_require_published_checksum_file(self):
        self.add_history()
        self.assets["hypopg"]["/releases/tags/v0"]["assets"].pop()
        self.assertEqual(zip_count(self.generate()), 71)

    def test_latest_requires_license_and_prefers_per_pg_version(self):
        path, data = self.add_history()
        data["upstream"]["perPostgresql"] = {"15": {"version": "2.4"}}
        path.write_text(json.dumps(data))
        current = latest(self.generate()["extensions"][0])
        self.assertEqual({p["pgMajor"]: p["version"] for p in current["packages"]},
                         {"14": "1.0", "15": "2.4", "16": "1.0", "17": "1.0", "18": "1.0"})
        del data["releaseInventory"]["current"]["licensesByMajor"]["15"]
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "license evidence"):
            self.generate()

    def test_history_does_not_extend_supported_majors(self):
        path, data = self.add_history()
        old = data["releaseInventory"]["history"][0]["packages"][0]
        old.update(pgMajor="14", asset=old["asset"].replace("pg15", "pg14"))
        record = self.admissions[ADMISSION, "hypopg"]
        record["postgresql"]["14"] = {**record["postgresql"].pop("15"), "asset": old["asset"]}
        record["upstream"]["perPostgresql"]["14"] = record["upstream"]["perPostgresql"].pop("15")
        licenses = record["releaseInventory"]["current"]["licensesByMajor"]
        licenses["14"] = licenses.pop("15")
        path.write_text(json.dumps(data))
        config = self.root / "config/cli-feed-majors.json"
        config.write_text(json.dumps({"schemaVersion": 1, "postgresqlMajors": ["15", "16", "17", "18"]}))
        self.assertEqual([r["releaseTag"] for r in self.generate()["extensions"][0]["releases"]], ["v1"])

    def test_actual_release_note_formatter_tracks_latest_and_total(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/cli-signed-catalog-feed.yml").read_text()
        code = textwrap.dedent(workflow.split("<<'FEED_NOTES_PY'\n", 1)[1]
                              .split("          FEED_NOTES_PY\n", 1)[0])
        self.add_history()
        source, notes = self.root / "feed.json", self.root / "notes.md"
        feed = self.generate()
        source.write_bytes(canonical(feed))
        result = subprocess.run([sys.executable, "-c", code, str(source), str(notes)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = notes.read_text()
        self.assertIn("14 Catalog-approved extensions", output)
        self.assertIn("70 latest, 71 total including history", output)
        self.assertIn("PostgreSQL majors 14, 15, 16, 17, 18", output)
        self.assertIn("元ZIPは最新版70件、履歴を含めて計71件", output)
        self.assertIn("INTEGRITY_ONLY", output)
        self.assertLess(output.index("## English"), output.index("## 日本語"))

        source.write_bytes(canonical({**feed, "publicationAuthorized": True}))
        notes.unlink()
        result = subprocess.run([sys.executable, "-c", code, str(source), str(notes)],
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(notes.exists())


class CatalogAdmissionLoaderTests(unittest.TestCase):
    @patch("scripts.cli_signed_feed.get_api_json")
    def test_uses_catalog_contents_at_exact_protected_commit(self, api):
        api.return_value = {"type": "file", "path": "extensions/hypopg.json",
                            "encoding": "base64", "content": base64.encodebytes(b'{}').decode()}
        self.assertEqual(get_catalog_record(ADMISSION, "hypopg", "job-token", lambda: {ADMISSION}), {})
        api.assert_called_once_with(
            f"https://api.github.com/repos/pgextwin/catalog/contents/extensions/hypopg.json?ref={ADMISSION}",
            "job-token")
        api.reset_mock()
        with self.assertRaisesRegex(ValueError, "outside protected main"):
            get_catalog_record(ADMISSION, "hypopg", "job-token", lambda: {SHA})
        api.assert_not_called()

    def test_extension_api_still_denies_contents_routes(self):
        with self.assertRaisesRegex(ValueError, "Unexpected Release route"):
            get_repo_json("pgextwin/hypopg", f"/contents/extensions/hypopg.json?ref={ADMISSION}")


if __name__ == "__main__":
    unittest.main()
