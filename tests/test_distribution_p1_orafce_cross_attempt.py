#!/usr/bin/env python3
"""Hostile exact-identity cross-attempt observations. No synthetic Sigstore PASS."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from distribution_manifest_v1 import Denied
import distribution_p1_orafce_cross_attempt as cross


class CrossAttemptHostile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.observed = cross._read_pinned(cross.OBSERVED, cross.OBSERVED_BLOB)
        cls.source = {"upstreamRepository": "orafce/orafce",
                      "upstreamRef": "VERSION_4_16_13",
                      "upstreamCommit": "e538f81acccf73bd9c40977e22e8c4984e452622"}

    def test_four_exact_zip_to_original_signed_build_and_publication_continuity(self):
        self.assertEqual({r["pgMajor"] for r in self.observed["rows"]},
                         {14, 15, 16, 17})
        for major in (14, 15, 16, 17):
            with self.subTest(major=major):
                x = cross._log_continuity(self.observed, str(major), self.source)
                self.assertEqual(len(x["originalCheckoutLogSha256"]), 64)
                self.assertEqual(len(x["originalArtifactTransferSha256"]), 64)
                self.assertEqual(x["publisherOriginalLogGitBlob"],
                                 cross.PUBLISH_BLOB)

    def test_attempt1_failure_and_attempt2_publication_not_interchangeable(self):
        run = lambda n: {"id": cross.RUN, "run_attempt": n,
                         "head_sha": cross.SHA, "event": "push",
                         "path": ".github/workflows/windows.yml",
                         "status": "completed", "conclusion":
                             "failure" if n == 1 else "success",
                         "repository": {"id": 1413246504}}
        target = self.observed["rows"][0]
        job = {"id": target["buildJobId"],
               "name": "release_build / PostgreSQL 14 / Windows x64",
               "run_attempt": 1, "head_sha": cross.SHA, "conclusion": "success"}
        publisher = {"id": cross.PUBLISH, "name": "release / Publish GitHub Release",
                     "run_attempt": 2, "head_sha": cross.SHA,
                     "conclusion": "success"}
        response = {
            "repos/pgextwin/orafce/actions/runs/38062983035/attempts/1": run(1),
            "repos/pgextwin/orafce/actions/runs/38062983035/attempts/2": run(2),
            "repos/pgextwin/orafce/actions/runs/38062983035/attempts/1/jobs?per_page=100":
                {"jobs": [job], "total_count": 1},
            "repos/pgextwin/orafce/actions/runs/38062983035/attempts/2/jobs?per_page=100":
                {"jobs": [publisher], "total_count": 1},
        }
        def check(messages):
            with patch.object(cross, "_gh_json", side_effect=lambda path: messages[path]):
                return cross._authentic_attempts(self.observed, "14")
        result = check(response)
        self.assertEqual(result["originalBuildAttempt"], 1)
        self.assertEqual(result["finalPublicationAttempt"], 2)
        self.assertEqual(result["originalRunAttempt1Conclusion"], "failure")
        for case, key, value in (
            ("false-run-success", "run1-conclusion", "success"),
            ("failed-build", "build-conclusion", "failure"),
            ("wrong-build-attempt", "build-attempt", 2),
            ("failed-publisher", "publisher-conclusion", "failure"),
            ("wrong-publisher-id", "publisher-id", 99),
            ("wrong-publisher-attempt", "publisher-attempt", 1),
            ("replayed-run-source", "run2-head", "f"*40),
        ):
            data = copy.deepcopy(response)
            if key == "run1-conclusion":
                data["repos/pgextwin/orafce/actions/runs/38062983035/attempts/1"]["conclusion"] = value
            elif key == "build-conclusion":
                data["repos/pgextwin/orafce/actions/runs/38062983035/attempts/1/jobs?per_page=100"]["jobs"][0]["conclusion"] = value
            elif key == "build-attempt":
                data["repos/pgextwin/orafce/actions/runs/38062983035/attempts/1/jobs?per_page=100"]["jobs"][0]["run_attempt"] = value
            elif key == "publisher-conclusion":
                data["repos/pgextwin/orafce/actions/runs/38062983035/attempts/2/jobs?per_page=100"]["jobs"][0]["conclusion"] = value
            elif key == "publisher-id":
                data["repos/pgextwin/orafce/actions/runs/38062983035/attempts/2/jobs?per_page=100"]["jobs"][0]["id"] = value
            elif key == "publisher-attempt":
                data["repos/pgextwin/orafce/actions/runs/38062983035/attempts/2/jobs?per_page=100"]["jobs"][0]["run_attempt"] = value
            elif key == "run2-head":
                data["repos/pgextwin/orafce/actions/runs/38062983035/attempts/2"]["head_sha"] = value
            with self.subTest(case=case), self.assertRaises(Denied):
                check(data)

    def test_no_different_repo_pg_run_asset_or_upstream_trust(self):
        for name, major in (("plpgsql_check", "14"), ("pg_bigm", "14"),
                            ("orafce", "18"), ("wal2json", "15"),
                            ("orafce", "19")):
            with self.subTest(name=name, major=major), self.assertRaises(Denied):
                cross.probe_original_cross_attempt(
                    name=name, major=major,
                    pin={"runId":cross.RUN, "runAttempt":2,
                         "releaseId":409043426, "packagingSha":cross.SHA},
                    release={"id":409043426, "target_commitish":cross.SHA},
                    config={}, row={}, folder=Path("."), hashes={},
                    trusted_root=None, root_sha="", cache={})
        for key, bad in (
            ("upstreamRepository", "evil/repo"),
            # Full-SHA checkout logs intentionally do not assert the tag.
            # Historical upstream config independently authenticates ref.
            ("upstreamCommit", "0"*40),
        ):
            src=dict(self.source,**{key:bad})
            with self.subTest(key=key), self.assertRaises(Denied):
                cross._log_continuity(self.observed,"14",src)
        with patch.object(cross, "PUBLISH_BLOB", "0"*40):
            with self.assertRaises(Denied):
                cross._log_continuity(self.observed,"14",self.source)
        with patch.object(cross, "OBSERVED_BLOB", "f"*40):
            with self.assertRaises(Denied):
                cross._read_pinned(cross.OBSERVED,cross.OBSERVED_BLOB)

    def test_malicious_non_get_attempt_url_rejected(self):
        for path in ("repos/pgextwin/plpgsql_check/actions/runs/38062983035/attempts/1",
                     "repos/pgextwin/orafce/actions/runs/38128142145/attempts/1",
                     "repos/pgextwin/orafce/actions/runs/38062983035/attempts/3",
                     "repos/pgextwin/orafce/actions/runs/38062983035/attempts/2/rerun"):
            with self.subTest(path=path), self.assertRaises(Denied):
                cross._gh_json(path)


if __name__ == "__main__":
    unittest.main()
