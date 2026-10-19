import hashlib
import json
import tempfile
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


if __name__ == "__main__":
    unittest.main()
