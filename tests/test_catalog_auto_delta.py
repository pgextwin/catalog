#!/usr/bin/env python3
"""Catalog unattended discovery fixtures; no Release verification is faked."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("catalog_auto_delta", ROOT / "scripts" / "catalog_auto_delta.py")
# The scripts/ directory must be importable for verified_release_record.
import sys
sys.path.insert(0, str(ROOT / "scripts"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
NAMES = sorted(mod.INTAKE_ALLOWED)


def _v3_index(names):
    return {
        "schemaVersion": 3,
        "identitiesDir": "identities",
        "packagesDir": "packages",
        "extensions": list(names),
        "identities": [
            {
                "name": n,
                "path": f"identities/{n}.json",
                "intakeClass": "distributed",
                "ledgerPath": f"packages/{n}.json",
            }
            for n in sorted(names)
        ],
    }


def _ledger(name, release_id, tag="v1.0-windows.1", published_at="2026-10-20T01:00:00Z"):
    return {
        "schemaVersion": 1,
        "name": name,
        "repository": "pgextwin/" + name,
        "latestReleaseId": release_id,
        "releases": [{
            "releaseId": release_id,
            "releaseTag": tag,
            "publishedAt": published_at,
            "packages": [],
        }],
    }


def fixture():
    index = _v3_index(NAMES)
    records = {name: _ledger(name, i + 1) for i, name in enumerate(NAMES)}
    published = {name: [
        {"id": i + 1, "tag_name": "v1.0-windows.1", "draft": False,
         "prerelease": False, "published_at": "2026-10-20T01:00:00Z"}
    ] for i, name in enumerate(NAMES)}
    return index, records, published, []


def newer(x, name="orafce", tag="v4.17.1-windows.1"):
    x[2][name].append({"id": 999, "tag_name": tag, "draft": False,
                        "prerelease": False,
                        "published_at": "2026-10-22T02:00:00Z"})


class ReconcileTests(unittest.TestCase):
    def test_no_change_is_no_job_and_never_publishes(self):
        x = fixture()
        self.assertEqual(mod.discover(*x), {"include": []})

    def test_only_new_public_release_is_proposed_for_signed_verification(self):
        x = fixture()
        newer(x)
        self.assertEqual(mod.discover(*x)["include"],
                         [{"extension": "orafce", "release_tag": "v4.17.1-windows.1"}])

    def test_duplicate_record_proposal_prevents_duplicate_run(self):
        x = fixture()
        newer(x)
        x[3].append({"state": "open",
                     "headRef": "auto-catalog/orafce-v4.17.1-windows.1"})
        self.assertEqual(mod.discover(*x)["include"], [])

    def test_manual_dispatch_is_unchanged(self):
        x = fixture()
        self.assertEqual(mod.discover(*x, manual=("pgtap", "v1.3.4-windows.1")),
                         {"include": [{"extension": "pgtap",
                                      "release_tag": "v1.3.4-windows.1"}]})

    def test_draft_and_prerelease_never_trigger(self):
        x = fixture()
        newer(x)
        x[2]["orafce"][-1]["draft"] = True
        self.assertEqual(mod.discover(*x)["include"], [])
        x[2]["orafce"][-1]["draft"] = False
        x[2]["orafce"][-1]["prerelease"] = True
        self.assertEqual(mod.discover(*x)["include"], [])

    def test_fail_closed_on_corrupt_or_downgrade(self):
        cases = [
            lambda x: x[0]["extensions"].pop(),
            lambda x: x[0]["extensions"].append(NAMES[0]),
            lambda x: x[0].update(schemaVersion=True),
            lambda x: x[0].update(schemaVersion=2),
            lambda x: x[0]["identities"].append({
                "name": "http", "path": "identities/http.json",
                "intakeClass": "research-only", "ledgerPath": "packages/http.json"}),
            lambda x: x[1].pop(NAMES[0]),
            lambda x: x[1][NAMES[0]].update(repository="pgextwin/evil"),
            lambda x: x[1][NAMES[0]].update(schemaVersion=2),
            lambda x: x[1][NAMES[0]]["releases"][0].update(releaseTag="../evil"),
            lambda x: x[1][NAMES[0]]["releases"][0].update(admission={"catalogCommit": "a" * 40}),
            lambda x: x[2][NAMES[0]].clear(),
            lambda x: x[2][NAMES[0]][0].update(id=0),
            lambda x: x[2][NAMES[0]][0].update(published_at="garbage"),
            lambda x: x[3].append({"state": "open", "headRef": 4}),
        ]
        for i, case in enumerate(cases):
            with self.subTest(case=i), self.assertRaises(mod.Denied):
                x = fixture()
                case(x)
                mod.discover(*x)
        x = fixture()
        newer(x)
        x[1]["orafce"]["releases"][0]["publishedAt"] = "2026-10-23T00:00:00Z"
        with self.assertRaises(mod.Denied):
            mod.discover(*x)

    def test_future_registered_extension_uses_same_exact_roster_without_fixed_count(self):
        with patch.dict(mod.INTAKE_ALLOWED, {"future_ext": "example/future_ext"}):
            index, records, published, prs = fixture()
            index["extensions"].append("future_ext")
            index["identities"].append({
                "name": "future_ext", "path": "identities/future_ext.json",
                "intakeClass": "distributed", "ledgerPath": "packages/future_ext.json"})
            records["future_ext"] = _ledger("future_ext", 500)
            published["future_ext"] = [{
                "id": 500, "tag_name": "v1.0-windows.1",
                "draft": False, "prerelease": False,
                "published_at": "2026-10-20T01:00:00Z"}]
            self.assertEqual(mod.discover(index, records, published, prs),
                             {"include": []})
            published["future_ext"].append({
                "id": 501, "tag_name": "v1.1-windows.1",
                "draft": False, "prerelease": False,
                "published_at": "2026-10-23T01:00:00Z"})
            self.assertEqual(mod.discover(index, records, published, prs),
                             {"include": [{"extension": "future_ext",
                                           "release_tag": "v1.1-windows.1"}]})
            # No change may auto-register an unapproved, differently named repo.
            index["extensions"].append("evil")
            index["identities"].append({
                "name": "evil", "path": "identities/evil.json",
                "intakeClass": "distributed", "ledgerPath": "packages/evil.json"})
            records["evil"] = _ledger("evil", 502)
            published["evil"] = list(published["future_ext"])
            with self.assertRaises(mod.Denied):
                mod.discover(index, records, published, prs)

    def test_explicit_future_first_release_without_placeholder_record(self):
        with patch.dict(mod.INTAKE_ALLOWED, {"future_ext": "source/future_ext"}), \
             patch.dict(mod.FIRST_RELEASE_SOURCES, {"future_ext": "source/future_ext"}), \
             patch.dict(mod.FIRST_RELEASE, {
                 "future_ext": ("Future", "Reviewed signed extension", "PostgreSQL")
             }):
            index, records, published, prs = fixture()
            # Existing Catalog index/records remain untouched. Registered
            # future identities do not require fake unsigned placeholders.
            published["future_ext"] = []
            self.assertEqual(mod.discover(index, records, published, prs),
                             {"include": []})
            published["future_ext"] = [
                {"id": 818, "tag_name": "v1.0-windows.1",
                 "draft": False, "prerelease": False,
                 "published_at": "2026-10-24T12:00:00Z"}]
            self.assertEqual(mod.discover(index, records, published, prs),
                             {"include": [{"extension": "future_ext",
                                           "release_tag": "v1.0-windows.1"}]})
            prs.append({"state": "open",
                        "headRef": "auto-catalog/future_ext-v1.0-windows.1"})
            self.assertEqual(mod.discover(index, records, published, prs),
                             {"include": []})
            prs.clear()
            published["future_ext"][0]["prerelease"] = True
            self.assertEqual(mod.discover(index, records, published, prs),
                             {"include": []})

    def test_unseeded_missing_or_unregistered_record_never_auto_intakes(self):
        index, records, published, prs = fixture()
        with patch.dict(mod.INTAKE_ALLOWED, {"future_ext": "source/future_ext"}):
            published["future_ext"] = []
            with self.assertRaises(mod.Denied):
                mod.discover(index, records, published, prs)
        missing = NAMES[0]
        index["extensions"].remove(missing)
        index["identities"] = [e for e in index["identities"] if e["name"] != missing]
        del records[missing]
        # Removing a previously distributed/established extension cannot
        # masquerade as a brand-new first Release.
        with self.assertRaises(mod.Denied):
            mod.discover(index, records, published, prs)

    def test_mixed_failed_publisher_and_eligible_release_candidates_stay_independent(self):
        """Discovery does not grant either tag admission; each matrix row is verified."""
        x = fixture()
        # The known failed Publisher-origin HypoPG tag is intentionally present.
        # It must not authorize itself or suppress another future eligible tag.
        newer(x, name="hypopg", tag="v1.4.4-windows.1")
        newer(x, name="orafce", tag="v4.17.1-windows.1")
        expected = [
            {"extension": "hypopg", "release_tag": "v1.4.4-windows.1"},
            {"extension": "orafce", "release_tag": "v4.17.1-windows.1"},
        ]
        self.assertEqual(mod.discover(*x)["include"], expected)
        workflow = (ROOT / ".github" / "workflows" / "sync-verified-release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("fail-fast: false", workflow)
        self.assertIn("max-parallel: 1", workflow)
        self.assertIn("matrix: ${{ fromJSON(needs.discover.outputs.targets) }}", workflow)
        self.assertIn("python scripts/verify_signed_fleet_release.py", workflow)
        self.assertIn('--extension "$EXTENSION" --release-tag "$RELEASE_TAG"', workflow)
        # If a HypoPG candidate has a pending record-only PR, only that exact
        # row is deduplicated. The unrelated new stable update remains eligible
        # for its *own* stringent signed provenance / public byte verification.
        x[3].append({
            "state": "open",
            "headRef": "auto-catalog/hypopg-v1.4.4-windows.1",
        })
        self.assertEqual(mod.discover(*x)["include"], [expected[1]])

    def test_invalid_manual_release_target_rejected(self):
        x = fixture()
        for target in [("evil", "v1.0-windows.1"), ("orafce", "blah"),
                       ("orafce", "../evil"), ("orafce", "")]:
            with self.subTest(target=target), self.assertRaises(mod.Denied):
                mod.discover(*x, manual=target)

    def test_main_reads_identities_candidate_index_and_packages_without_root_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(ROOT / "identities", root / "identities")
            shutil.copytree(ROOT / "packages", root / "packages")
            out_file = root / "gh_out.txt"

            class FakeReader:
                def __init__(self, token):
                    pass

                def get(self, relative):
                    if relative == "repos/pgextwin/catalog/pulls?state=open&base=main&per_page=100":
                        return []
                    name = relative.split("/")[2]
                    ledger = json.loads((root / "packages" / f"{name}.json").read_text("utf-8"))
                    cur = mod.package_ledger.current_release(ledger)
                    return [{"id": cur["releaseId"], "tag_name": cur["releaseTag"],
                             "draft": False, "prerelease": False, "published_at": cur["publishedAt"]}]

            env = {
                "GITHUB_REPOSITORY": "pgextwin/catalog",
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "schedule",
                "GH_TOKEN": "read-token",
                "GITHUB_OUTPUT": str(out_file),
            }
            with patch.dict(os.environ, env, clear=False), \
                 patch.object(mod, "GithubReader", FakeReader), \
                 patch("sys.argv", ["catalog_auto_delta.py", "--catalog-root", str(root)]):
                self.assertEqual(mod.main(), 0)
            out = out_file.read_text("utf-8")
            self.assertIn("has_changes=false\n", out)

            # Corrupting an identity causes main() to fail closed.
            bad_id = json.loads((root / "identities" / "orafce.json").read_text("utf-8"))
            bad_id["intake"]["expectedUpstreamRepository"] = "evil/orafce"
            (root / "identities" / "orafce.json").write_text(json.dumps(bad_id), "utf-8")
            with patch.dict(os.environ, env, clear=False), \
                 patch.object(mod, "GithubReader", FakeReader), \
                 patch("sys.argv", ["catalog_auto_delta.py", "--catalog-root", str(root)]):
                self.assertEqual(mod.main(), 2)


if __name__ == "__main__":
    unittest.main()
