"""Fail-closed fixtures for the explicit historical pilot. NO fixture is signed evidence."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import distribution_historical_p1_pg14 as h
import distribution_release_verify_p1 as ordinary
from distribution_manifest_v1 import Denied

P = h.PIN


def bundle(predicate, sha=None, name=None):
    subject = {"name": name or P["asset"],
               "digest": {"sha256": sha or P["zipSha256"]}}
    st = {"_type": "https://in-toto.io/Statement/v1",
          "predicateType": predicate, "subject": [subject],
          "predicate": ({"spdxVersion": "SPDX-2.3"} if predicate == h.SPDX else
                        {"buildDefinition": {}, "runDetails": {}})}
    return {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json",
                             "payload": base64.b64encode(json.dumps(st).encode()).decode(),
                             "signatures": [{"sig": base64.b64encode(b"FAKE").decode()}]},
            "verificationMaterial": {"certificate": {"rawBytes": "FAKE"},
                                     "tlogEntries": [{"logIndex": "FAKE"}]}}


def listing(bundles=None):
    bb = bundles or [bundle(h.PROVENANCE), bundle(h.SPDX)]
    return ("\n".join(json.dumps({"bundle": b}) for b in bb) + "\n").encode()


def certificate(predicate=h.SPDX):
    repo = P["repo"]
    signer = "https://github.com/" + h.SIGNER + "@" + P["signerSha"]
    return {
        "issuer": h.ISSUER, "sourceRepositoryURI": "https://github.com/" + repo,
        "sourceRepositoryIdentifier": str(P["repoId"]),
        "sourceRepositoryDigest": P["packaging"],
        "sourceRepositoryRef": P["sourceRef"],
        "runInvocationURI": f"https://github.com/{repo}/actions/runs/{P['runId']}/attempts/1",
        "buildTrigger": "push",
        "buildSignerURI": signer, "subjectAlternativeName": signer,
        "buildSignerDigest": P["signerSha"],
        "githubWorkflowSHA": P["packaging"], "githubWorkflowRef": P["sourceRef"],
        "buildConfigURI": ("https://github.com/" + repo +
                           "/.github/workflows/windows.yml@" + P["sourceRef"]),
        "buildConfigDigest": P["packaging"],
    }


def verified_output(predicate=h.SPDX):
    statement = {"predicateType": predicate,
                 "subject": [{"name": P["asset"],
                              "digest": {"sha256": P["zipSha256"]}}],
                 "predicate": ({"spdxVersion": "SPDX-2.3"} if predicate == h.SPDX else
                               {"runDetails": {"metadata": {"invocationId":
                                   f"https://github.com/{P['repo']}/actions/runs/{P['runId']}/attempts/1"},
                                               "builder": {"id": "builder"}},
                                "buildDefinition": {"buildType": "foo"}})}
    return [{"verificationResult": {
        "statement": statement, "signature": {"certificate": certificate(predicate)},
        "verifiedTimestamps": [{"timestamp": "synthetic"}],
    }}]


def run_data():
    return {
        "id": P["runId"], "run_attempt": 1, "path": ".github/workflows/windows.yml",
        "event": "push", "head_sha": P["packaging"],
        "head_branch": "release/v1.2-20250903-windows.2",
        "status": "completed", "conclusion": "success",
        "repository": {"id": P["repoId"], "full_name": P["repo"]},
    }


def jobs_data():
    return {"jobs": [
        {"id": P["pgJobId"], "name": "release_build / PostgreSQL 14 / Windows x64",
         "conclusion": "success", "run_attempt": 1, "head_sha": P["packaging"]},
        {"id": P["publishJobId"], "name": "release / Publish GitHub Release",
         "conclusion": "success", "run_attempt": 1, "head_sha": P["packaging"]},
    ]}


class HistoricalP1Tests(unittest.TestCase):
    def deny(self, callback, *args, **kwargs):
        with self.assertRaises(Denied):
            callback(*args, **kwargs)

    def test_two_raw_bundles_object_preserved_not_cryptographic(self):
        orig = listing()
        result, receipt = h.normalize_jsonl(orig, name=P["asset"], digest=P["zipSha256"])
        self.assertEqual(set(result), set(h.PREDICATES))
        self.assertEqual(receipt["wrapperSha256"], hashlib.sha256(orig).hexdigest())
        for predicate in h.PREDICATES:
            obj = json.loads(result[predicate])
            self.assertEqual(obj, bundle(predicate))
            self.assertEqual(hashlib.sha256(result[predicate]).hexdigest(),
                             receipt["normalized"][predicate]["rawBundleSha256"])
        self.assertNotIn("signatureVerified", receipt)

    def test_wrapper_unknown_duplicate_and_noncanonical_structures(self):
        data = listing()
        self.deny(h.normalize_jsonl, data.replace(b'{"bundle":', b'{"extra":0,"bundle":'),
                  name=P["asset"], digest=P["zipSha256"])
        dup = data.replace(b'{"bundle":', b'{"bundle":{},"bundle":')
        self.deny(h.normalize_jsonl, dup, name=P["asset"], digest=P["zipSha256"])
        self.deny(h.normalize_jsonl, data + b"\n", name=P["asset"], digest=P["zipSha256"])
        self.deny(h.normalize_jsonl, b"x" * (h.MAX_JSONL + 1),
                  name=P["asset"], digest=P["zipSha256"])
        self.deny(h.normalize_jsonl, data.replace(b'{"bundle":', b'{"bundle_extra":'),
                  name=P["asset"], digest=P["zipSha256"])

    def test_duplicate_and_mixed_predicates(self):
        self.deny(h.normalize_jsonl, listing([bundle(h.SPDX), bundle(h.SPDX)]),
                  name=P["asset"], digest=P["zipSha256"])
        self.deny(h.normalize_jsonl, listing([bundle(h.PROVENANCE), bundle(h.PROVENANCE)]),
                  name=P["asset"], digest=P["zipSha256"])
        mutated = bundle(h.SPDX)
        mutated["verificationMaterial"]["unknown"] = "ignored by gh"
        # Material is untrusted; real verification must still run.
        raw, _ = h.normalize_jsonl(listing([bundle(h.PROVENANCE), mutated]),
                                   name=P["asset"], digest=P["zipSha256"])
        self.assertEqual(set(raw), set(h.PREDICATES))

    def test_subject_and_bundle_forgery(self):
        cases = [
            [bundle(h.PROVENANCE, sha="f"*64), bundle(h.SPDX)],
            [bundle(h.PROVENANCE), bundle(h.SPDX, name="pg15.zip")],
        ]
        for bb in cases:
            self.deny(h.normalize_jsonl, listing(bb), name=P["asset"], digest=P["zipSha256"])
        bb = [bundle(h.PROVENANCE), bundle(h.SPDX)]
        bb[0]["unknown"] = True
        self.deny(h.normalize_jsonl, listing(bb), name=P["asset"], digest=P["zipSha256"])
        bb = [bundle(h.PROVENANCE), bundle(h.SPDX)]
        bb[1]["dsseEnvelope"]["signatures"] = []
        self.deny(h.normalize_jsonl, listing(bb), name=P["asset"], digest=P["zipSha256"])
        bb[1]["dsseEnvelope"]["signatures"] = [{"sig": "RkFLRQ=="}, {"sig": "RkFLRQ=="}]
        self.deny(h.normalize_jsonl, listing(bb), name=P["asset"], digest=P["zipSha256"])

    def test_unsigned_gh_output_not_accepted(self):
        self.deny(h._certified, [], predicate=h.SPDX, sbom={"spdxVersion":"SPDX-2.3"})
        self.deny(h._certified, [{"verificationResult":{"statement":{}}}],
                  predicate=h.SPDX, sbom={"spdxVersion":"SPDX-2.3"})
        self.deny(h._certified, verified_output(h.SPDX),
                  predicate=h.SPDX, sbom={"spdxVersion":"SPDX-2.3", "tampered":True})

    def test_historical_certificate_policy_and_hostile_claims(self):
        sbom = {"spdxVersion":"SPDX-2.3"}
        # Synthetic gh-style output exercises only policy, not real crypto.
        h._certified(verified_output(), predicate=h.SPDX, sbom=sbom)
        h._certified(verified_output(h.PROVENANCE), predicate=h.PROVENANCE, sbom=sbom)
        for key, replacement in (
            ("sourceRepositoryIdentifier", "999"),
            ("sourceRepositoryURI", "https://github.com/pgextwin/plpgsql_check"),
            ("buildTrigger", "workflow_dispatch"),
            ("sourceRepositoryRef", "refs/heads/main"),
            ("githubWorkflowRef", "refs/heads/main"),
            ("sourceRepositoryDigest", "a"*40),
            ("buildSignerDigest", "a"*40),
            ("subjectAlternativeName", "fake"),
            ("runInvocationURI", "https://github.com/pgextwin/pg_bigm/actions/runs/2/attempts/2"),
            ("buildConfigURI", "https://github.com/pgextwin/pg_bigm/.github/workflows/promote.yml@refs/heads/main"),
            ("buildConfigDigest", "b"*40),
            ("issuer", "fake"),
        ):
            out = verified_output()
            out[0]["verificationResult"]["signature"]["certificate"][key] = replacement
            self.deny(h._certified, out, predicate=h.SPDX, sbom=sbom)
        out = verified_output()
        out[0]["verificationResult"]["verifiedTimestamps"] = []
        self.deny(h._certified, out, predicate=h.SPDX, sbom=sbom)
        out = verified_output()
        out[0]["verificationResult"]["statement"]["subject"] = []
        self.deny(h._certified, out, predicate=h.SPDX, sbom=sbom)

    def test_wrong_run_event_ref_attempt_job_or_publish(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            def write(run=None, jobs=None):
                (root/"run.json").write_text(json.dumps(run or run_data()), encoding="utf-8")
                (root/"jobs.json").write_text(json.dumps(jobs or jobs_data()), encoding="utf-8")
                (root/"pg14-job.log").write_text(
                    "Complete job name: release_build / PostgreSQL 14 / Windows x64\n"
                    + "repository: " + P["upstreamRepo"] + "\nref: "
                    + P["upstreamRef"] + "\n" + P["upstreamSha"], encoding="utf-8")
                (root/"upstream-commit.json").write_text(json.dumps({
                    "sha": P["upstreamSha"], "parents": [{"sha":"a"*40}]}), encoding="utf-8")
            write()
            h.validate_run_jobs(root)
            for field, value in [
                ("event", "workflow_dispatch"), ("path", ".github/workflows/promote.yml"),
                ("run_attempt", 2), ("head_sha", "f"*40),
                ("head_branch", "main"), ("conclusion", "failure")]:
                r = run_data()
                r[field] = value
                write(run=r)
                self.deny(h.validate_run_jobs, root)
            for field, value in [
                ("run_attempt", 2), ("conclusion", "failure"),
                ("name", "release_build / PostgreSQL 15 / Windows x64")]:
                j = jobs_data()
                j["jobs"][0][field] = value
                write(jobs=j)
                self.deny(h.validate_run_jobs, root)
            j = jobs_data()
            j["jobs"][1]["conclusion"] = "failure"
            write(jobs=j)
            self.deny(h.validate_run_jobs, root)
            write()
            (root/"pg14-job.log").unlink()
            self.deny(h.validate_run_jobs, root)
            write()
            (root/"upstream-commit.json").write_text('{"sha":"'+ "f"*40 +'","parents":[]}')
            self.deny(h.validate_run_jobs, root)

    def test_origin_and_unsigned_package_denied(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for n in ("windows.yml", "extension.json"):
                (root/n).write_text("forged", encoding="utf-8")
            self.deny(h.validate_package_and_origin, root, {"buildMode":"release-attested"})

    def test_asset_id_and_sha_bytes_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            row={"asset": P["asset"], "sha256": P["zipSha256"],
                 "evidence": {"sbom":{"asset":"x.spdx.json"},
                              "vulnerabilityReport":{"asset":"x.vulnerabilities.json"}}}
            (root/"assets").mkdir()
            (root/"assets"/P["asset"]).write_bytes(b"FORGED")
            self.deny(h.validate_row_bytes, root, {}, row,
                      {P["asset"]:{"size":29490, "digest":"sha256:"+P["zipSha256"]}})

    def test_catalog_pin_and_no_automatic_historical_mode(self):
        with tempfile.TemporaryDirectory() as d:
            self.deny(h.validate_fixed_catalog, Path(d), "f"*40)
            self.deny(h.audit, Path(d), Path(d)/"root", P["catalog"])
            with patch.object(h, "verify_offline_gh", side_effect=AssertionError("must not run")):
                self.deny(h.audit, Path(d), Path(d)/"root", P["catalog"])
        self.assertIn("head_branch", ordinary.signed_run.__code__.co_consts)
        self.assertNotEqual(h.PIN["sourceRef"], "refs/heads/main")

    def test_real_gh_does_not_start_with_missing_trusted_root(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(h.subprocess, "run", side_effect=AssertionError("forbidden")):
                self.deny(h.verify_offline_gh, Path(d)/"zip", {},
                          {h.PROVENANCE:b"fake",h.SPDX:b"fake"}, Path(d)/"root")

    def test_plpgsql_check_failed_promotion_never_eligible(self):
        self.assertEqual(h.PIN["repo"], "pgextwin/pg_bigm")
        self.assertNotEqual(h.PIN["runId"], 38128142145)
        with tempfile.TemporaryDirectory() as d:
            self.deny(h.validate_fixed_catalog, Path(d), h.PIN["catalog"])


if __name__ == "__main__":
    unittest.main()
