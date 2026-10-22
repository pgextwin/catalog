#!/usr/bin/env python3
"""Catalog unattended discovery fixtures; no Release verification is faked."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("catalog_auto_delta", ROOT / "scripts" / "catalog_auto_delta.py")
# The scripts/ directory must be importable for verified_release_record.
import sys
sys.path.insert(0, str(ROOT / "scripts"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
NAMES = sorted(mod.INTAKE_ALLOWED)


def fixture():
    index = {"schemaVersion": 2, "extensions": list(NAMES)}
    records = {name: {"schemaVersion": 2, "name": name,
                       "repository": "pgextwin/" + name,
                       "latest": {"releaseTag": "v1.0-windows.1",
                                  "publishedAt": "2026-10-20T01:00:00Z"}}
               for name in NAMES}
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
            lambda x: x[1].pop(NAMES[0]),
            lambda x: x[1][NAMES[0]].update(repository="pgextwin/evil"),
            lambda x: x[1][NAMES[0]]["latest"].update(releaseTag="../evil"),
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
        x[1]["orafce"]["latest"]["publishedAt"] = "2026-10-23T00:00:00Z"
        with self.assertRaises(mod.Denied):
            mod.discover(*x)

    def test_invalid_manual_release_target_rejected(self):
        x = fixture()
        for target in [("evil", "v1.0-windows.1"), ("orafce", "blah"),
                       ("orafce", "../evil"), ("orafce", "")]:
            with self.subTest(target=target), self.assertRaises(mod.Denied):
                mod.discover(*x, manual=target)


if __name__ == "__main__":
    unittest.main()
