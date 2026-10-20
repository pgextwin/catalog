#!/usr/bin/env python3
"""Issue #75: hostile no-network one-shot fleet canary tests."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import sys
from unittest import TestCase, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import catalog_fleet14_readonly as fleet

SHA = "a" * 40
OTHER_SHA = "b" * 40
ALL = tuple(sorted(fleet.ALLOWED))


class FakeAPI:
    def __init__(self, *, advance_main=False, advance_pr=False, dup_pr=False):
        self.calls = []
        self.main_reads = 0
        self.pr_reads = 0
        self.advance_main = advance_main
        self.advance_pr = advance_pr
        self.dup_pr = dup_pr

    def get(self, repo, path):
        self.calls.append((repo, path))
        if repo != fleet.MAIN_REPO:
            raise AssertionError("unexpected repo request")
        if path == "branches/main":
            self.main_reads += 1
            sha = OTHER_SHA if self.advance_main and self.main_reads == 2 else SHA
            return {"protected": True, "commit": {"sha": sha}}
        if path == fleet.PR_PATH:
            self.pr_reads += 1
            original = [{"number": 11, "state": "open",
                         "base": {"ref": "main"},
                         "head": {"sha": "c" * 40}}]
            if self.dup_pr:
                return original * 2
            if self.advance_pr and self.pr_reads == 2:
                original[0]["head"]["sha"] = "d" * 40
            return original
        raise AssertionError("unexpected path: " + path)


def result(extension, *, status="NO_CHANGE", catalog_sha=SHA):
    return {
        "extension": extension,
        "status": status,
        "catalogMainSha": catalog_sha,
        "snapshotCount": 2,
        "source": "authenticated-github-readonly",
        "catalogTag": "v1.0-windows.1",
        "candidateTag": "v1.0-windows.1",
        "openRecordProposalPrs": [] if status != "BLOCKED_OPEN_RECORD_PR" else [77],
        "publishableReceipt": False,
        "proposalAuthorized": False,
        "mutationsEnabled": False,
        "verifiedSignedRelease": False,
    }


class Fleet14Tests(TestCase):
    def test_full_14_metadata_same_and_no_mutation(self):
        api = FakeAPI()
        with mock.patch.object(fleet, "audit", side_effect=lambda a, e: result(e)) as audit:
            proof = fleet.audit_fleet(api, expected_main_sha=SHA)
        self.assertEqual(audit.call_count, 14)
        self.assertEqual([x.args[1] for x in audit.call_args_list], list(ALL))
        self.assertEqual(proof["fleetSize"], 14)
        self.assertEqual(proof["status"], "FLEET_METADATA_NO_CHANGE")
        self.assertEqual(proof["catalogMainSha"], SHA)
        self.assertEqual(proof["snapshotCountPerExtension"], 2)
        self.assertFalse(proof["fleetWideAtomicSnapshot"])
        for key in ("verifiedSignedRelease", "proposalAuthorized",
                    "mutationsEnabled", "publishableReceipt"):
            self.assertIs(proof[key], False)
        self.assertEqual(api.main_reads, 2)
        self.assertEqual(api.pr_reads, 2)
        self.assertEqual(len(proof["extensions"]), 14)

    def test_new_release_is_report_only_never_proposed(self):
        with mock.patch.object(fleet, "audit", side_effect=lambda a, e: result(
                e, status="VERIFY_SIGNED_RELEASE_FIRST"
                if e == "wal2json" else "NO_CHANGE")):
            proof = fleet.audit_fleet(FakeAPI(), expected_main_sha=SHA)
        self.assertEqual(proof["status"], "FLEET_REQUIRES_INDEPENDENT_RELEASE_REVIEW")
        self.assertIs(proof["proposalAuthorized"], False)
        self.assertIs(proof["publishableReceipt"], False)

    def test_existing_record_pr_blocks_duplicate_without_writing(self):
        with mock.patch.object(fleet, "audit", side_effect=lambda a, e: result(
                e, status="BLOCKED_OPEN_RECORD_PR"
                if e == "pg_bigm" else "NO_CHANGE")):
            proof = fleet.audit_fleet(FakeAPI(), expected_main_sha=SHA)
        self.assertEqual(proof["status"], "FLEET_REQUIRES_INDEPENDENT_RELEASE_REVIEW")
        record = next(z for z in proof["extensions"] if z["extension"] == "pg_bigm")
        self.assertEqual(record["openRecordProposalPrs"], [77])
        self.assertFalse(proof["mutationsEnabled"])

    def test_main_or_open_pr_toctou_denied(self):
        for variant in ({"advance_main": True}, {"advance_pr": True},
                        {"dup_pr": True}):
            with self.subTest(variant=variant):
                with mock.patch.object(fleet, "audit",
                                       side_effect=lambda a, e: result(e)):
                    with self.assertRaises(fleet.Denied):
                        fleet.audit_fleet(FakeAPI(**variant), expected_main_sha=SHA)

    def test_any_one_of_14_missing_mismatched_or_unverified_denied(self):
        mutations = (
            lambda v: v.update(extension="unknown"),
            lambda v: v.update(catalogMainSha=OTHER_SHA),
            lambda v: v.update(snapshotCount=1),
            lambda v: v.update(status="VERIFIED_SIGNED_RELEASE"),
            lambda v: v.update(proposalAuthorized=True),
            lambda v: v.update(publishableReceipt=True),
            lambda v: v.update(verifiedSignedRelease=True),
            lambda v: v.update(mutationsEnabled=True),
            lambda v: v.update(source="untrusted"),
            lambda v: v.update(openRecordProposalPrs=[77, 77]),
            lambda v: v.update(openRecordProposalPrs=["untrusted"]),
            lambda v: v.update(openRecordProposalPrs=[77]),
            lambda v: v.pop("catalogTag"),
        )
        for i, mutation in enumerate(mutations):
            def hostile(api, extension):
                value = result(extension)
                if extension == "pg_bigm":
                    mutation(value)
                return value
            with self.subTest(i=i):
                with mock.patch.object(fleet, "audit", side_effect=hostile):
                    with self.assertRaises(fleet.Denied):
                        fleet.audit_fleet(FakeAPI(), expected_main_sha=SHA)

    def test_missing_ambiguous_or_wrong_protected_main_denied(self):
        class BadApi(FakeAPI):
            def get(self, repo, path):
                if path == "branches/main":
                    return {"protected": False, "commit": {"sha": SHA}}
                return super().get(repo, path)
        with mock.patch.object(fleet, "audit",
                               side_effect=lambda a, e: result(e)):
            for sha in ("short", OTHER_SHA):
                with self.subTest(sha=sha), self.assertRaises(fleet.Denied):
                    fleet.audit_fleet(FakeAPI(), expected_main_sha=sha)
            with self.assertRaises(fleet.Denied):
                fleet.audit_fleet(BadApi(), expected_main_sha=SHA)

    def test_runtime_rejects_dispatch_pr_schedule_wrong_repo_and_secret(self):
        env = {"GITHUB_REPOSITORY": fleet.MAIN_REPO,
               "GITHUB_REF": "refs/heads/main",
               "GITHUB_EVENT_NAME": "push", "GITHUB_SHA": SHA,
               "GITHUB_TOKEN": "fixture-token"}
        for changes in (
            {"GITHUB_REPOSITORY": "pgextwin/build"},
            {"GITHUB_REF": "refs/heads/dev"},
            {"GITHUB_EVENT_NAME": "workflow_dispatch"},
            {"GITHUB_EVENT_NAME": "schedule"},
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"GITHUB_SHA": "bad"},
            {"GITHUB_TOKEN": ""},
        ):
            with mock.patch.dict(os.environ, dict(env, **changes), clear=True):
                with mock.patch.object(
                        fleet, "GitHubReadOnly", side_effect=lambda token:
                        (fleet.require(bool(token), "missing token"), FakeAPI())[1]):
                    self.assertEqual(fleet.main(), 2)

    def test_one_shot_workflow_is_exact_main_path_and_read_only(self):
        txt = (ROOT / "tests/fixtures/historical-workflows/catalog-fleet14-readonly-canary.yml").read_text()
        for expected in (
            "name: Catalog 14-extension read-only canary (Issue 75)",
            "on:\n  push:\n    branches:\n      - main",
            ".github/workflows/catalog-fleet14-readonly-canary.yml",
            "permissions:\n  contents: read",
            "github.repository == 'pgextwin/catalog'",
            "github.event_name == 'push'",
            "github.ref == 'refs/heads/main'",
            "ref: ${{ github.sha }}",
            "persist-credentials: false",
            "python scripts/catalog_fleet14_readonly.py",
            "DRY_RUN_FLEET14_METADATA_ONLY",
        ):
            self.assertIn(expected, txt)
        for forbidden in (
            "\n  schedule:", "\n  pull_request:", "\n  workflow_dispatch:",
            "\n  workflow_call:", "\n  release:", "\n  repository_dispatch:",
            "contents: write", "pull-requests: write", "actions: write",
            "create-github-app-token", "upload-artifact", "secrets.",
            "gh pr create", "gh release ", "git push", "gh workflow run ",
        ):
            self.assertNotIn(forbidden, txt)
        self.assertEqual(txt.count("python scripts/catalog_fleet14_readonly.py"), 1)


if __name__ == "__main__":
    import unittest
    unittest.main()
