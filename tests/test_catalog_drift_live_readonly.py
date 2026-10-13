#!/usr/bin/env python3
"""Issue #75 Phase D: authenticated read-only source snapshot allow/deny tests.

All HTTP responses, remote metadata and newer public Releases are synthetic.
No network, proposer, verified signature, publisher or state mutation.
"""
from copy import deepcopy
import base64
import io
import json
from pathlib import Path
import sys
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import catalog_drift_live_readonly as live
from test_catalog_release_drift import fixture, future_release

MAIN = "08e3d48abc6cab71f8b735091cc5bbe6095abcf6"
CAT = "pgextwin/catalog"
EXT = "pgextwin/wal2json"
RECORD_PATH = "extensions/wal2json.json"


def encoded_record(record):
    raw = json.dumps(record, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return {"encoding": "base64", "content": base64.b64encode(raw).decode("ascii"),
            "sha": live.blob_sha(raw)}


def snapshots():
    record, releases = fixture()
    return {
        (CAT, "branches/main"): {"commit": {"sha": MAIN}},
        (CAT, "contents/" + RECORD_PATH + "?ref=" + MAIN): encoded_record(record),
        (EXT, "releases?per_page=100&page=1"): releases,
        (CAT, "pulls?state=open&base=main&per_page=100"): [],
    }


class FakeApi:
    def __init__(self, values):
        self.values = values

    def get(self, repo, path):
        if (repo, path) not in self.values:
            raise live.Denied("missing authenticated snapshot")
        return deepcopy(self.values[(repo, path)])


class SnapshotTests(TestCase):
    def test_live_shape_existing_release_remains_noop(self):
        result = live.inspect(FakeApi(snapshots()), "wal2json")
        self.assertEqual(result["status"], "NO_CHANGE")
        self.assertEqual(result["catalogMainSha"], MAIN)
        self.assertEqual(result["publicReleaseCount"], 2)
        self.assertTrue(result["gitHubCollectionsComplete"])
        self.assertFalse(result["verifiedSignedRelease"])
        self.assertFalse(result["proposalAuthorized"])
        self.assertFalse(result["mutationsEnabled"])

    def test_new_release_must_not_trigger_proposal_before_signature_proof(self):
        obj = snapshots()
        obj[(EXT, "releases?per_page=100&page=1")].append(future_release())
        result = live.inspect(FakeApi(obj), "wal2json")
        self.assertEqual(result["status"], "VERIFY_SIGNED_RELEASE_FIRST")
        self.assertEqual(result["candidateArtifactsAndAttestation"], "NOT_VERIFIED")
        self.assertFalse(result["proposalAuthorized"])

    def test_any_open_pr_touching_extension_blocks_duplicate_proposal(self):
        obj = snapshots()
        obj[(EXT, "releases?per_page=100&page=1")].append(future_release())
        obj[(CAT, "pulls?state=open&base=main&per_page=100")] = [
            {"number": 77, "state": "open", "base": {"ref": "main"}}]
        obj[(CAT, "pulls/77/files?per_page=100")] = [
            {"filename": RECORD_PATH, "status": "modified"}]
        outcome = live.inspect(FakeApi(obj), "wal2json")
        self.assertEqual(outcome["status"], "BLOCKED_OPEN_RECORD_PR")
        self.assertEqual(outcome["openRecordProposalPrs"], [77])
        self.assertFalse(outcome["proposalAuthorized"])

    def test_read_failure_missing_history_and_forged_record_are_denied(self):
        changes = [
            lambda o: o[(CAT,"branches/main")]["commit"].update(sha="a"),
            lambda o: o[(CAT,"contents/"+RECORD_PATH+"?ref="+MAIN)].update(sha="a"*40),
            lambda o: o[(CAT,"contents/"+RECORD_PATH+"?ref="+MAIN)].update(content="!!!"),
            lambda o: o[(EXT,"releases?per_page=100&page=1")].clear(),
            lambda o: o[(EXT,"releases?per_page=100&page=1")].extend(
                deepcopy(o[(EXT,"releases?per_page=100&page=1")]) * 50),
            lambda o: o[(CAT,"pulls?state=open&base=main&per_page=100")].extend(
                [{"number": i, "state": "open", "base": {"ref": "main"}}
                 for i in range(1, 101)]),
            lambda o: o.pop((CAT, "branches/main")),
        ]
        for i, change in enumerate(changes):
            obj = snapshots()
            change(obj)
            with self.subTest(case=i), self.assertRaises(live.Denied):
                live.inspect(FakeApi(obj), "wal2json")

    def test_ambiguous_pr_and_partial_file_list_are_denied(self):
        obj = snapshots()
        pr = {"number": 77, "state": "open", "base": {"ref": "main"}}
        obj[(CAT,"pulls?state=open&base=main&per_page=100")] = [pr, deepcopy(pr)]
        with self.assertRaises(live.Denied):
            live.inspect(FakeApi(obj), "wal2json")
        obj[(CAT,"pulls?state=open&base=main&per_page=100")] = [pr]
        obj[(CAT,"pulls/77/files?per_page=100")] = [{"filename":"README.md"}] * 100
        with self.assertRaises(live.Denied):
            live.inspect(FakeApi(obj), "wal2json")

    def test_rest_get_is_read_only_and_link_next_denied(self):
        for link, denied in [
            ("", False),
            ('<https://api.github.com/repos/pgextwin/wal2json/releases?page=2>; rel="next"', True),
        ]:
            with self.subTest(link=link):
                response = io.BytesIO(b"[]")
                response.status = 200
                response.headers = {"Link": link}
                with mock.patch.object(live, "urlopen", return_value=response) as request:
                    api = live.GitHubReadOnly("test-read-token")
                    if denied:
                        with self.assertRaises(live.Denied):
                            api.get(EXT, "releases?per_page=100&page=1")
                    else:
                        self.assertEqual(api.get(EXT, "releases?per_page=100&page=1"), [])
                    self.assertEqual(request.call_args.args[0].get_method(), "GET")


if __name__ == "__main__":
    main()
