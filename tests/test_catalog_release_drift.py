#!/usr/bin/env python3
"""No-network Phase D drift fixtures; wal2json metadata from published v2.7.

Only timestamps, stable flags, tags and pinned target SHAs are real here.
The asset rows and hypothetical future release are synthetic placeholders;
this does NOT test cryptographic signature verification.
"""
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location(
    "catalog_drift", ROOT / "scripts" / "catalog_release_drift.py")
drift = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drift)


def fixture():
    record = {
        "schemaVersion": 1,
        "name": "wal2json",
        "repository": "pgextwin/wal2json",
        "latestReleaseId": 452157205,
        "releases": [
            {
                "releaseTag": "v2.7-windows.1",
                "releaseId": 452157205,
                "publishedAt": "2026-10-12T09:46:28Z",
                "packages": [],
            }
        ],
    }
    releases = [
        {"tag_name": "v2.6-windows.1", "draft": False, "prerelease": False,
         "published_at": "2026-10-10T08:06:12Z",
         "target_commitish": "ba62a237ff044990cce26b279c3f0a936bb95ad6",
         "assets": [{"name": "synthetic-placeholder"}]},
        {"tag_name": "v2.7-windows.1", "draft": False, "prerelease": False,
         "published_at": "2026-10-12T09:46:28Z",
         "target_commitish": "1198ff30137ee3fd01a9e168647a7167324bb713",
         "assets": [{"name": "synthetic-placeholder"}]},
    ]
    return record, releases


def identity_fixture():
    return {
        "schemaVersion": 1,
        "name": "wal2json",
        "upstreamRepository": "eulerto/wal2json",
        "description": "Logical decoding output plugin emitting JSON",
        "intake": {
            "class": "distributed",
            "distributionAllowed": True,
            "registrationSource": "historical-core",
            "expectedUpstreamRepository": "eulerto/wal2json",
            "sealedUpstream": True,
        },
        "distribution": {
            "repository": "pgextwin/wal2json",
            "license": "BSD-3-Clause",
            "ledgerPath": "packages/wal2json.json",
        },
    }


def future_release():
    return {
        "tag_name": "v2.8-windows.1", "draft": False, "prerelease": False,
        "published_at": "2026-10-13T00:00:00Z",
        "target_commitish": "a" * 40,
        "assets": [{"name": "synthetic-placeholder"}],
    }


class DriftTests(unittest.TestCase):
    def assert_inert(self, result):
        self.assertFalse(result["verifiedSignedRelease"])
        self.assertFalse(result["proposalAuthorized"])
        self.assertFalse(result["mutationsEnabled"])

    def test_existing_wal2json_2_7_is_no_change(self):
        record, releases = fixture()
        result = drift.classify(record, releases, identity=identity_fixture())
        self.assertEqual(result["status"], "NO_CHANGE")
        self.assertEqual(result["candidateTag"], "v2.7-windows.1")
        self.assert_inert(result)

    def test_future_candidate_must_pass_independent_signed_verification(self):
        record, releases = fixture()
        releases.append(future_release())
        result = drift.classify(record, releases, identity=identity_fixture())
        self.assertEqual(result["status"], "VERIFY_SIGNED_RELEASE_FIRST")
        self.assertEqual(result["candidateTag"], "v2.8-windows.1")
        self.assert_inert(result)
        existing = drift.classify(record, releases, pending_tags=["v2.8-windows.1"], identity=identity_fixture())
        self.assertEqual(existing["status"], "EXISTING_PROPOSAL")
        self.assert_inert(existing)
        conflicting = drift.classify(record, releases, pending_tags=["v2.7-windows.2"], identity=identity_fixture())
        self.assertEqual(conflicting["status"], "BLOCKED_CONFLICT")
        self.assert_inert(conflicting)

    def test_rollback_missing_or_ambiguous_release_denied(self):
        changes = [
            lambda rec, releases: rec["releases"][0].update(publishedAt="2026-10-13T01:00:00Z"),
            lambda rec, releases: rec["releases"][0].update(releaseTag="v2.8-windows.1"),
            lambda rec, releases: rec.update(schemaVersion=2),
            lambda rec, releases: rec.update(latestReleaseId=999999999),
            lambda rec, releases: rec["releases"].append(deepcopy(rec["releases"][0])),
            lambda rec, releases: rec["releases"][0].update(admission={"catalogCommit": "a" * 40}),
            lambda rec, releases: releases.append(deepcopy(releases[1])),
            lambda rec, releases: releases[1].update(published_at=None),
            lambda rec, releases: releases[0].update(published_at=releases[1]["published_at"]),
            lambda rec, releases: releases[1].update(target_commitish="not-pinned"),
            lambda rec, releases: releases[1].update(assets=[]),
            lambda rec, releases: releases[1].update(draft=True),
            lambda rec, releases: releases[1].update(prerelease=True),
            lambda rec, releases: rec.update(repository="pgextwin/evil"),
            lambda rec, releases: releases.clear(),
            lambda rec, releases: releases.extend(deepcopy(releases) * 49),
        ]
        for idx, change in enumerate(changes):
            record, releases = fixture()
            change(record, releases)
            with self.subTest(index=idx), self.assertRaises(drift.Denied):
                drift.classify(record, releases)

    def test_mismatched_identity_denied(self):
        record, releases = fixture()
        identity_changes = [
            lambda ident: ident.update(name="hypopg"),
            lambda ident: ident["intake"].update({"class": "research-only", "distributionAllowed": False}),
            lambda ident: ident["intake"].update(expectedUpstreamRepository="evil/wal2json"),
            lambda ident: ident.update(upstreamRepository="evil/wal2json"),
            lambda ident: ident["distribution"].update(repository="pgextwin/evil"),
            lambda ident: ident["distribution"].update(ledgerPath="packages/evil.json"),
        ]
        for idx, change in enumerate(identity_changes):
            ident = identity_fixture()
            change(ident)
            with self.subTest(idx=idx), self.assertRaises(drift.Denied):
                drift.classify(record, releases, identity=ident)

    def test_pending_list_and_future_release_fail_closed(self):
        record, releases = fixture()
        releases.append(future_release())
        for pending in [["v2.8-windows.1", "v2.8-windows.1"],
                        ["../evil"], ["v2.7-windows.2", "v2.8-windows.1", "v2.8-windows.1"]]:
            with self.subTest(pending=pending), self.assertRaises(drift.Denied):
                drift.classify(record, releases, pending_tags=pending)
        releases[2]["target_commitish"] = "z" * 40
        with self.assertRaises(drift.Denied):
            drift.classify(record, releases)


if __name__ == "__main__":
    unittest.main()
