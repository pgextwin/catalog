"""Offline negative tests for authenticated, read-only external Windows Release discovery."""
import copy
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import discover_external_windows_releases as d  # noqa: E402

CONFIG = json.loads((ROOT / "external/discovery-providers-v1.json").read_text())
PROVIDERS = d.config_providers(CONFIG)
BASELINES = [
    json.loads((ROOT / p).read_text())
    for p in ("evidence/issue112-external-release-inventory-20261103.json",
              "evidence/issue112-external-provider-portalcorp-20261103.json")
]


def sample(repo="portalcorp/pgvector_compiled", name="pgvector-Windows-pg16.zip"):
    return {"id": 301, "tag_name": "v0.16.10", "published_at": "2024-07-30T20:54:47Z",
            "draft": False, "prerelease": False, "assets": [{
                "id": 401, "name": name, "size": 1234, "digest": None,
                "browser_download_url": f"https://github.com/{repo}/releases/download/v0.16.10/{name}",
                "state": "uploaded"}]}


class DiscoveryTests(unittest.TestCase):
    def test_pinned_baselines_all_match_explicit_windows_patterns(self):
        self.assertEqual(5, len(PROVIDERS))
        for p in PROVIDERS:
            if p["repo"] == "trickle-labs/pg-trickle":
                continue  # New provider has no pinned historical baseline yet.
            historical = next(repo for b in BASELINES for repo in b["repositories"]
                              if repo["repo"] == p["repo"])
            names = [a["name"] for r in historical["releases"] for a in r["windowsAssets"]]
            self.assertTrue(names)
            for name in names:
                self.assertRegex(name, re.compile(p["assetPattern"]))
        self.assertEqual(203, sum(r["windowsAssets"] for b in BASELINES
                                  for r in b["repositories"]))

    def test_page_terminal_and_metadata_denial(self):
        portal = PROVIDERS[-1]
        rows = d.summarize_pages(portal, [[sample()], []])
        self.assertEqual(2, rows["pagesScanned"])
        self.assertEqual(1, rows["windowsAssets"])
        snapshot = d.scan([portal], lambda repo, page: [sample()] if page == 1 else [])
        self.assertFalse(snapshot["publicationAuthorized"])
        self.assertFalse(snapshot["redistributionAuthorized"])
        self.assertEqual("UNVERIFIED_METADATA_ONLY", snapshot["trust"])
        self.assertNotIn("downloadAuthorized", rows["releases"][0]["windowsAssets"][0])

    def test_source_archive_is_not_windows_dll(self):
        portal = PROVIDERS[-1]
        src = sample(name="pgvector-source.zip")
        self.assertEqual(0, d.summarize_pages(portal, [[src], []])["windowsAssets"])

    def test_invalid_url_and_duplicate_asset_fail_closed(self):
        portal = PROVIDERS[-1]
        bad = sample()
        bad["assets"][0]["browser_download_url"] = "https://evil.example/x"
        with self.assertRaises(ValueError):
            d.summarize_pages(portal, [[bad], []])
        bad = sample()
        bad["assets"].append(copy.deepcopy(bad["assets"][0]))
        with self.assertRaises(ValueError):
            d.summarize_pages(portal, [[bad], []])

    def test_page_truncation_and_duplicate_release_rejected(self):
        portal = PROVIDERS[-1]
        with self.assertRaises(ValueError):
            d.summarize_pages(portal, [[sample()]])
        with self.assertRaises(ValueError):
            d.summarize_pages(portal, [[sample()], [sample()], []])

    def test_no_cross_repo_or_insecure_config(self):
        bad = copy.deepcopy(CONFIG)
        bad["providers"][0]["repo"] = "https://evil.invalid/a"
        with self.assertRaises(ValueError):
            d.config_providers(bad)
        bad = copy.deepcopy(CONFIG)
        bad["providers"].append(copy.deepcopy(bad["providers"][0]))
        with self.assertRaises(ValueError):
            d.config_providers(bad)
        bad = copy.deepcopy(CONFIG)
        bad["trust"] = "AUTHORIZED"
        with self.assertRaises(ValueError):
            d.config_providers(bad)

    def test_changed_digest_flags_review_not_authorization(self):
        old = {"repositories": [{
            "repo": "portalcorp/pgvector_compiled",
            "releases": [{"releaseId": 301, "tag": "v0.16.10", "windowsAssets": [{
                "assetId": 401, "name": "pgvector-Windows-pg16.zip",
                "size": 1234, "digest": None, "url":
                "https://github.com/portalcorp/pgvector_compiled/releases/download/v0.16.10/pgvector-Windows-pg16.zip",
                "state": "uploaded"}]}]}]}
        current = d.scan([PROVIDERS[-1]],
                         lambda repo, page: [sample()] if page == 1 else [])
        self.assertEqual(0, d.compare(current, [old])["changed"])
        modified = copy.deepcopy(current)
        modified["repositories"][0]["releases"][0]["windowsAssets"][0]["size"] += 1
        self.assertEqual(1, d.compare(modified, [old])["changed"])
        self.assertFalse(modified["publicationAuthorized"])

    def test_pg_trickle_exact_upstream_windows_name_stays_untrusted(self):
        provider = next(p for p in PROVIDERS if p["repo"] == "trickle-labs/pg-trickle")
        self.assertEqual("upstream-official", provider["providerType"])
        self.assertEqual("pg_trickle", provider["extension"])
        latest = {
            "id": 404988260, "tag_name": "v0.108.3",
            "published_at": "2026-10-06T17:39:38Z",
            "draft": False, "prerelease": False,
            "assets": [{
                "id": 616203967,
                "name": "pg_trickle-0.108.3-pg18-windows-amd64.zip",
                "size": 7029107,
                "digest": "sha256:c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b",
                "state": "uploaded",
                "browser_download_url":
                    "https://github.com/trickle-labs/pg-trickle/releases/download/v0.108.3/"
                    "pg_trickle-0.108.3-pg18-windows-amd64.zip",
            }],
        }
        snapshot = d.scan([provider], lambda repo, page: [latest] if page == 1 else [])
        row = snapshot["repositories"][0]
        self.assertEqual(1, row["windowsAssets"])
        self.assertEqual(0, row["windowsAssetsMissingDigest"])
        self.assertFalse(snapshot["publicationAuthorized"])
        self.assertFalse(snapshot["redistributionAuthorized"])
        self.assertEqual("UNVERIFIED_METADATA_ONLY", snapshot["trust"])
        self.assertNotIn("downloadAuthorized", row["releases"][0]["windowsAssets"][0])

    def test_pg_trickle_excludes_old_name_and_other_pg_major(self):
        provider = next(p for p in PROVIDERS if p["repo"] == "trickle-labs/pg-trickle")
        pattern = re.compile(provider["assetPattern"])
        self.assertIsNone(pattern.fullmatch("pg_stream-0.1.1-pg18-windows-amd64.zip"))
        self.assertIsNone(pattern.fullmatch("pg_trickle-0.108.3-pg17-windows-amd64.zip"))
        self.assertIsNone(pattern.fullmatch("pg_trickle-0.108.3-pg18-linux-amd64.tar.gz"))
        self.assertIsNotNone(pattern.fullmatch("pg_trickle-0.108.3-pg18-windows-amd64.zip"))
        row = sample(repo=provider["repo"],
                     name="pg_trickle-0.108.3-pg18-windows-amd64.zip")
        row["assets"][0]["browser_download_url"] = "https://evil.invalid/replacement.zip"
        with self.assertRaises(ValueError):
            d.summarize_pages(provider, [[row], []])

    def test_readonly_and_no_publisher_imports(self):
        source = (ROOT / "scripts/discover_external_windows_releases.py").read_text()
        self.assertNotIn("POST", source)
        self.assertNotIn("DELETE", source)
        self.assertNotIn("workflow_dispatch", source)
        self.assertNotIn("releases/upload", source)


if __name__ == "__main__":
    unittest.main()
