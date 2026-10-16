#!/usr/bin/env python3
"""Offline hostile contract: no fixture or mocked gh may grant genuine P1 PASS."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from distribution_manifest_v1 import Denied
import distribution_p1_historical_fleet as history
import distribution_p1_batch as batch
from distribution_release_verify_p1 import verify_sigstore_offline


class HistoricalFleetHostile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.policy = json.loads((root / "config/issue112-p1-fleet-pins-20261017.json").read_text())
        cls.raw = (root / "config/issue112-p1-historical-source-pins-20261017.json").read_bytes()
        cls.pins = history.pins_load(cls.raw, cls.policy)

    def test_exact_12_pin_release_source_and_attempts(self):
        self.assertEqual(len(self.pins), 12)
        self.assertEqual({p["signerSha"] for p in self.pins.values()}, history.OLD_SIGNERS)
        self.assertEqual(self.pins["orafce"]["runAttempt"], 2)
        self.assertEqual(self.pins["pg_bigm"]["runAttempt"], 1)
        self.assertNotIn("wal2json", self.pins)
        self.assertNotIn("plpgsql_check", self.pins)
        self.assertEqual(sum(x["name"] != "pg_bigm" for x in self.pins.values()) * 5 + 4, 59)

    def test_unpinned_signer_source_profile_or_future_pg_deny(self):
        for field, bad in (
            ("signerSha", "0"*40), ("runId", 38128142145),
            ("runAttempt", 3), ("releaseId", 1), ("repositoryId", 2),
            ("packagingSha", "0"*40), ("sourceRef", "refs/heads/main"),
            ("sourceRef", "refs/heads/release/../../evil"),
            ("configBlob", "INVALID"), ("workflowBlob", "f"*39),
        ):
            doc = json.loads(self.raw)
            doc["items"][0][field] = bad
            with self.subTest(field=field, bad=bad), self.assertRaises(Denied):
                history.pins_load(json.dumps(doc).encode(), self.policy)
        doc = json.loads(self.raw)
        doc["items"].append(copy.deepcopy(doc["items"][0]))
        with self.assertRaises(Denied):
            history.pins_load(json.dumps(doc).encode(), self.policy)

    def test_original_run_requires_correct_source_workflow_attempt_and_success(self):
        p = self.pins["orafce"]
        pkg = {
            "workflowRun": {
                "id": p["runId"], "attempt": 2, "event": "push",
                "ref": p["sourceRef"],
                "url": f"https://github.com/pgextwin/orafce/actions/runs/{p['runId']}",
            },
            "source": {"packagingRepository": "pgextwin/orafce",
                       "packagingCommit": p["packagingSha"]},
            "buildInfrastructure": {
                "repository": "pgextwin/build",
                "workflow": ".github/workflows/build-extension-attested.yml",
                "commit": p["signerSha"]},
        }
        run = {
            "id": p["runId"], "run_attempt": 2, "event": "push",
            "path": ".github/workflows/windows.yml",
            "head_branch": p["sourceRef"][11:], "head_sha": p["packagingSha"],
            "status": "completed", "conclusion": "success",
            "repository": {"id": p["repositoryId"], "full_name": "pgextwin/orafce"},
        }
        with patch.object(history, "api_json", return_value=run):
            self.assertEqual(history.historical_run("orafce", p, pkg)["id"], p["runId"])
        for field, val in (("run_attempt", 1), ("conclusion", "failure"),
                           ("path", ".github/workflows/promote.yml"),
                           ("head_sha", "f"*40), ("event", "workflow_dispatch"),
                           ("head_branch", "main")):
            with patch.object(history, "api_json", return_value=dict(run, **{field:val})):
                with self.subTest(field=field), self.assertRaises(Denied):
                    history.historical_run("orafce", p, pkg)
        for field, val in (("id", 1), ("attempt", 1),
                           ("event", "workflow_dispatch"), ("ref", "refs/heads/main")):
            item = copy.deepcopy(pkg)
            item["workflowRun"][field] = val
            with self.subTest(field=field), self.assertRaises(Denied):
                history.historical_run("orafce", p, item)

    def test_jobs_failure_duplicate_or_cross_attempt_deny(self):
        p = self.pins["hypopg"]
        base = [
            {"id": p["pgBuildJobIds"]["15"], "name": "release_build / PostgreSQL 15 / Windows x64",
             "conclusion": "success", "head_sha": p["packagingSha"], "run_attempt": 1},
            {"id": p["publishJobId"], "name": "release / Publish GitHub Release",
             "conclusion": "success", "head_sha": p["packagingSha"], "run_attempt": 1},
        ]
        base += [{"id": 100 + n, "name": "ancillary-" + str(n),
                  "conclusion": "skipped", "head_sha": p["packagingSha"],
                  "run_attempt": 1} for n in range(p["observedJobCount"] - 2)]
        def verify(jobs):
            proc = type("Proc", (), {"returncode": 0,
                    "stdout": json.dumps({"jobs": jobs, "total_count": len(jobs)}).encode()})()
            with patch.object(history.subprocess, "run", return_value=proc):
                return history.historical_jobs("hypopg", "15", p)
        self.assertEqual(verify(base)["publicationJobId"], p["publishJobId"])
        for bad in (
            [dict(base[0], conclusion="failure"), base[1]],
            [dict(base[0], run_attempt=2), base[1]],
            [dict(base[0], head_sha="f"*40), base[1]],
            [base[0], dict(base[1], conclusion="skipped")],
            [base[0], dict(base[1], name="Any publisher")],
            base+[dict(base[1], id=3)],
            [dict(base[0], id=999), *base[1:]],
        ):
            with self.subTest(bad=bad), self.assertRaises(Denied):
                verify(bad)

    def test_checkout_log_corroboration_required_and_job_id_pinned(self):
        p = self.pins["hypopg"]
        source = {"upstreamRepository": "HypoPG/hypopg",
                  "upstreamRef": "1.4.3",
                  "upstreamCommit": "21d5461ad1868434cc47d9aa656d7afc2b24c464"}
        original = (
            "Complete job name: release_build / PostgreSQL 15 / Windows x64\\n"
            "  repository: HypoPG/hypopg\\n"
            "  ref: 21d5461ad1868434cc47d9aa656d7afc2b24c464\\n"
            "21d5461ad1868434cc47d9aa656d7afc2b24c464\\n").replace("\\\\n", "\\n").encode()
        import io
        import hashlib
        class Resp(io.BytesIO):
            status = 200
            url = "https://api.github.com/repos/pgextwin/hypopg/actions/jobs/123/logs"
            def geturl(self):
                return self.url
        with patch("urllib.request.urlopen", return_value=Resp(original)) as get:
            proof = history.checkout_log_corrob("hypopg", "15", p, source)
            self.assertEqual(proof["originalCheckoutJobId"], p["pgBuildJobIds"]["15"])
            self.assertEqual(proof["originalCheckoutLogSha256"],
                             hashlib.sha256(original).hexdigest())
            request = get.call_args.args[0]
            self.assertEqual(request.get_method(), "GET")
            self.assertNotIn("Authorization", request.headers)
        for malicious in (original.replace(b"HypoPG/hypopg", b"other/repo"),
                          original.replace(source["upstreamCommit"].encode(), b"0"*40),
                          b"unrelated checkout evidence"):
            with patch("urllib.request.urlopen", return_value=Resp(malicious)):
                with self.assertRaises(Denied):
                    history.checkout_log_corrob("hypopg", "15", p, source)
        hostile = Resp(original)
        hostile.url = "http://evil.example/download"
        with patch("urllib.request.urlopen", return_value=hostile):
            with self.assertRaises(Denied):
                history.checkout_log_corrob("hypopg", "15", p, source)
        with patch("urllib.request.urlopen", side_effect=OSError("public logs unavailable")):
            with self.assertRaisesRegex(Denied, "BLOCKED"):
                history.checkout_log_corrob("hypopg", "15", p, source)

    def test_external_upstream_resolution_is_mandatory_not_pkg_self_assertion(self):
        upstream = {"repository":"sampleowner/samplerepo", "ref":"v1.2", "version":"1.2"}
        config = {"upstream":upstream}
        pkg={"upstream":dict(upstream,commit="a"*40)}
        good = type("P", (), {"returncode":0,
                              "stdout":json.dumps({"sha":"a"*40}).encode()})()
        with patch.object(history.subprocess, "run", return_value=good):
            self.assertEqual(history.historical_upstream("sample","15",config,pkg,cache={})["upstreamCommit"],"a"*40)
        bad = type("P", (), {"returncode":0,
                             "stdout":json.dumps({"sha":"b"*40}).encode()})()
        with patch.object(history.subprocess, "run", return_value=bad):
            with self.assertRaises(Denied):
                history.historical_upstream("sample","15",config,pkg,cache={})
        with patch.object(history.subprocess, "run", return_value=good):
            with self.assertRaises(Denied):
                history.historical_upstream("sample","15",config,
                    {"upstream":dict(upstream,commit="0"*40)},cache={})
        with patch.object(history.subprocess, "run", side_effect=OSError("offline")):
            with self.assertRaises(Denied):
                history.historical_upstream("sample","15",config,pkg,cache={})

    def test_crypto_profile_rejects_main_mixing_before_signature_check(self):
        with tempfile.TemporaryDirectory() as d:
            z = Path(d)/"asset.zip"
            r = Path(d)/"root"
            with self.assertRaises(Denied):
                verify_sigstore_offline(
                    z, {}, repo="pgextwin/hypopg",repo_id=1,packaging_sha="a"*40,
                    signer_sha="a"*40,run_id=1,attempt=1,root_path=r,
                    root_sha="a"*64,bundles={},
                    source_ref="refs/heads/main",build_trigger="push",
                    workflow_path="windows.yml")
            with self.assertRaises(Denied):
                verify_sigstore_offline(
                    z, {}, repo="pgextwin/hypopg",repo_id=1,packaging_sha="a"*40,
                    signer_sha="a"*40,run_id=1,attempt=1,root_path=r,
                    root_sha="a"*64,bundles={},
                    source_ref="refs/heads/release/foo",
                    build_trigger="workflow_dispatch",workflow_path="promote.yml")

    def test_formal_ledger_baseline_stays_six_without_new_cryptographic_receipts(self):
        source = Path(batch.__file__).read_text()
        self.assertIn('"formalP1Accepted": 6', source)
        self.assertIn('"historicalSourceAccepted": 0', source)
        self.assertNotIn('"publicationAuthorized": True', source)
        self.assertNotIn('"distributionAuthorized": True', source)


if __name__ == "__main__":
    unittest.main()
