#!/usr/bin/env python3
"""#75 scheduled Catalog read-only pilot: hostile offline test suite.

All GitHub release JSON fixtures here are synthetic. The protected-main
Actions run after a merge is the separate actual API acceptance.
"""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import sys
from unittest import TestCase, main, mock
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import catalog_scheduled_readonly as schedule
import catalog_drift_live_readonly as live
from test_catalog_drift_live_readonly import snapshots, FakeApi
from test_catalog_release_drift import future_release

CAT = "pgextwin/catalog"
EXT = "pgextwin/wal2json"
EXPECTED_TAG = "v2.7-windows.1"


class TwoRounds:
    def __init__(self, first, second=None):
        self.first = deepcopy(first)
        self.second = deepcopy(second if second is not None else first)
        self.rounds = 0
        self.paths = []

    def get(self, repo, path):
        if (repo, path) == (CAT, "branches/main"):
            self.rounds += 1
        self.paths.append((repo, path))
        data = self.first if self.rounds == 1 else self.second
        return FakeApi(data).get(repo, path)


class RunnerTests(TestCase):
    def test_no_change_wal2json_v27_with_two_independent_snapshots(self):
        api = TwoRounds(snapshots())
        result = schedule.audit(api)
        self.assertEqual(api.rounds, 2)
        self.assertEqual(len(api.paths), 8)
        self.assertEqual(result["status"], "NO_CHANGE")
        self.assertEqual(result["catalogTag"], EXPECTED_TAG)
        self.assertEqual(result["candidateTag"], EXPECTED_TAG)
        self.assertEqual(result["snapshotCount"], 2)
        self.assertFalse(result["publishableReceipt"])
        self.assertFalse(result["mutationsEnabled"])
        self.assertFalse(result["proposalAuthorized"])
        self.assertFalse(result["verifiedSignedRelease"])

    def test_new_public_release_requires_independent_signature_validation(self):
        records = snapshots()
        records[(EXT, "releases?per_page=100&page=1")].append(future_release())
        outcome = schedule.audit(TwoRounds(records))
        self.assertEqual(outcome["status"], "VERIFY_SIGNED_RELEASE_FIRST")
        self.assertFalse(outcome["proposalAuthorized"])
        self.assertFalse(outcome["mutationsEnabled"])
        self.assertFalse(outcome["verifiedSignedRelease"])

    def test_any_open_record_pr_blocks_duplicate_proposal(self):
        items = snapshots()
        items[(CAT, "pulls?state=open&base=main&per_page=100")] = [
            {"number": 77, "state": "open", "base": {"ref": "main"}},
        ]
        items[(CAT, "pulls/77/files?per_page=100")] = [
            {"filename": "extensions/wal2json.json", "status": "modified"},
        ]
        outcome = schedule.audit(TwoRounds(items))
        self.assertEqual(outcome["status"], "BLOCKED_OPEN_RECORD_PR")
        self.assertEqual(outcome["openRecordProposalPrs"], [77])
        self.assertFalse(outcome["proposalAuthorized"])

    def test_main_record_release_and_open_pr_toctou_denied(self):
        variants = []
        first = snapshots()
        second = deepcopy(first)
        second[(CAT, "branches/main")]["commit"]["sha"] = "c" * 40
        variants.append(second)

        second = deepcopy(first)
        second[(EXT, "releases?per_page=100&page=1")].append(future_release())
        variants.append(second)

        second = deepcopy(first)
        second[(CAT, "pulls?state=open&base=main&per_page=100")].append({
            "number": 77, "state": "open", "base": {"ref": "main"},
        })
        second[(CAT, "pulls/77/files?per_page=100")] = [
            {"filename": "extensions/wal2json.json", "status": "modified"}
        ]
        variants.append(second)

        second = deepcopy(first)
        key = (CAT, "contents/extensions/wal2json.json?ref="
               + "08e3d48abc6cab71f8b735091cc5bbe6095abcf6")
        second[key]["sha"] = "f" * 40
        variants.append(second)

        for n, changed in enumerate(variants):
            with self.subTest(n=n), self.assertRaises(live.Denied):
                schedule.audit(TwoRounds(first, changed))

    def test_partial_api_error_and_duplicate_pr_denied(self):
        snap = snapshots()
        missing = deepcopy(snap)
        missing.pop((EXT, "releases?per_page=100&page=1"))
        with self.assertRaises(live.Denied):
            schedule.audit(TwoRounds(snap, missing))
        duplicate = deepcopy(snap)
        duplicate[(CAT, "pulls?state=open&base=main&per_page=100")] = [
            {"number": 77, "state": "open", "base": {"ref": "main"}},
            {"number": 77, "state": "open", "base": {"ref": "main"}},
        ]
        with self.assertRaises(live.Denied):
            schedule.audit(TwoRounds(duplicate))

    def test_read_only_network_allowlist_http_denial_and_duplicate_fields(self):
        reader = live.GitHubReadOnly("synthetic-token")
        valid = [
            (CAT, "branches/main"),
            (CAT, "contents/extensions/wal2json.json?ref=" + "a" * 40),
            (CAT, "pulls?state=open&base=main&per_page=100"),
            (CAT, "pulls/77/files?per_page=100"),
            (EXT, "releases?per_page=100&page=1"),
        ]
        for repo, path in valid:
            reader.allowlisted(repo, path)

        forbidden = [
            (CAT, "contents/extensions/evil.json?ref=" + "a" * 40),
            (CAT, "contents/extensions/wal2json.json?ref=main"),
            (CAT, "pulls?state=closed&base=main&per_page=100"),
            (CAT, "pulls/77/merge"),
            (CAT, "actions/workflows/dispatches"),
            (EXT, "releases?per_page=1"),
            ("pgextwin/build", "branches/main"),
            (CAT, "../secrets"),
            (CAT, "pulls/1/files?per_page=100&evil=true"),
        ]
        for repo, path in forbidden:
            with self.subTest(repo=repo, path=path), self.assertRaises(live.Denied):
                reader.get(repo, path)
        source = (CAT, "branches/main")
        for code in (302, 403, 404, 429, 500):
            with mock.patch.object(reader, "_open", side_effect=HTTPError(
                    "https://api.github.com", code, "read failure", {}, None)):
                with self.subTest(code=code), self.assertRaises(live.Denied):
                    reader.get(*source)
        with mock.patch.object(reader, "_open", side_effect=URLError("network")):
            with self.assertRaises(live.Denied):
                reader.get(*source)
        payloads = (
            b'{"commit":{},"commit":{}}',
            b'{"broken"',
            b"[" + b"x" * (live.MAX_RESPONSE_BYTES + 1),
        )
        for raw in payloads:
            stream = io.BytesIO(raw)
            stream.status = 200
            stream.headers = {"Link": ""}
            with mock.patch.object(reader, "_open", return_value=stream):
                with self.assertRaises(live.Denied):
                    reader.get(*source)

    def test_main_environment_preflight_and_generic_error_message(self):
        good = {
            "GITHUB_REPOSITORY": CAT,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_TOKEN": "token-must-not-be-logged",
        }
        with mock.patch.dict(os.environ, good, clear=True):
            with mock.patch.object(schedule, "audit", return_value={
                "status": "NO_CHANGE", "publishableReceipt": False,
            }):
                with mock.patch.object(schedule, "GitHubReadOnly"):
                    self.assertEqual(schedule.main(), 0)
        for patch in (
            {"GITHUB_REPOSITORY": EXT},
            {"GITHUB_REF": "refs/heads/develop"},
            {"GITHUB_EVENT_NAME": "workflow_dispatch"},
            {"GITHUB_TOKEN": ""},
        ):
            env = dict(good, **patch)
            with mock.patch.dict(os.environ, env, clear=True):
                self.assertEqual(schedule.main(), 2)

    def test_workflow_no_dispatch_or_publication_ever(self):
        path = ROOT / ".github/workflows/catalog-drift-readonly.yml"
        text = path.read_text(encoding="utf-8")
        required = (
            "on:\n  schedule:",
            "cron: '30 0 * * *'",
            "  push:\n    branches:\n      - main",
            ".github/workflows/catalog-drift-readonly.yml",
            "permissions:\n  contents: read",
            "ref: ${{ github.sha }}",
            "persist-credentials: false",
            "github.repository == 'pgextwin/catalog'",
            "github.ref == 'refs/heads/main'",
            "github.event_name == 'schedule'",
            "python scripts/catalog_scheduled_readonly.py",
            "DRY_RUN_CATALOG_DRIFT_ONLY",
        )
        for key in required:
            self.assertIn(key, text)
        for forbidden in (
            "\n  workflow_dispatch:", "\n  pull_request:", "\n  workflow_call:",
            "\n  release:", "\n  repository_dispatch:",
            "contents: write", "pull-requests: write", "actions: write",
            "gh release ", "gh workflow run ", "git push", "gh pr create",
            "upload-artifact", "create-github-app-token", "secrets.",
        ):
            self.assertNotIn(forbidden, text)
        self.assertEqual(text.count("python scripts/catalog_scheduled_readonly.py"), 1)


if __name__ == "__main__":
    main()
