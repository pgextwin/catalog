#!/usr/bin/env python3
"""Hostile offline contract tests. Never claim to verify a real Sigstore signature."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import distribution_p1_batch as batch
from distribution_manifest_v1 import Denied


class GenuineBatchHostileTests(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "catalogCommitSha": "a" * 40, "rootSha256": "b" * 64,
            "repoIds": {"plpgsql_check": 123, "pg_bigm": 1405047175},
            "releaseIds": {"plpgsql_check": 456, "pg_bigm": 408449466},
            "assetIds": {}, "approvedMajors": [14, 15, 16, 17, 18],
            "officialGhSha256": ["c" * 64],
        }
        self.release = {"target_commitish": "d" * 40, "assets": [
            {"id": 3, "name": "plpgsql_check-test-pg15-windows-x64.zip",
             "size": 4, "digest": "sha256:" + "e" * 64}
        ]}

    def test_release_identity_not_reusable_for_other_ids_sources_profiles_roots(self):
        original = batch.identity(self.policy, "plpgsql_check", self.release)
        for change in ("asset", "assetid", "release", "repo", "source", "root",
                       "catalog", "verifier"):
            p = dict(self.policy)
            r = json.loads(json.dumps(self.release))
            if change == "asset":
                r["assets"][0]["digest"] = "sha256:" + "0" * 64
            elif change == "assetid":
                r["assets"][0]["id"] = 777
            elif change == "release":
                p["releaseIds"] = dict(p["releaseIds"], plpgsql_check=999)
            elif change == "repo":
                p["repoIds"] = dict(p["repoIds"], plpgsql_check=999)
            elif change == "source":
                r["target_commitish"] = "f" * 40
            elif change == "root":
                p["rootSha256"] = "f" * 64
            elif change == "catalog":
                p["catalogCommitSha"] = "0" * 40
            else:
                with patch.object(batch, "VERIFIER", "altered-verifier"):
                    self.assertNotEqual(batch.identity(p, "plpgsql_check", r), original)
                continue
            self.assertNotEqual(batch.identity(p, "plpgsql_check", r), original)

    def test_cache_rejects_altered_bytes_wrong_size_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            cache = Path(d)
            path = cache / "object"
            path.write_bytes(b"valid")
            digest = batch.sha(path)
            a = {"size": 5}
            batch.save_object(cache, path, a, digest)
            path.write_bytes(b"evil!")
            with self.assertRaises(Denied):
                batch.save_object(cache, path, a, digest)
            path.write_bytes(b"valid")
            with self.assertRaises(Denied):
                batch.save_object(cache, path, {"size": 4}, digest)
            cache_file = cache / "sha256" / digest
            cache_file.unlink()
            cache_file.symlink_to(path)
            with self.assertRaises(Denied):
                batch.save_object(cache, path, a, digest)

    def test_unpinned_gh_must_not_contact_github_or_touch_token(self):
        policy = dict(self.policy)
        policy["repoIds"] = {name: i + 100 for i, name in enumerate(batch.NAMES)}
        policy["releaseIds"] = {name: i + 200 for i, name in enumerate(batch.NAMES)}
        policy["assetIds"] = {name: {} for name in batch.NAMES}
        with tempfile.TemporaryDirectory() as d:
            with patch.object(batch, "require_gh", side_effect=Denied("bad executable")), \
                 patch.object(batch, "get_catalog") as get_catalog, \
                 patch.object(batch, "api_json") as api_json:
                report = batch.run(policy, Path(d) / "objects", Path(d) / "rows")
            get_catalog.assert_not_called()
            api_json.assert_not_called()
            self.assertEqual(report["formalP1Accepted"], 65)
            self.assertEqual(len(report["formalAcceptedBaseline"]), 65)
            self.assertEqual(report["verifiedCandidatesNotFormallyAdmitted"], [])
            self.assertEqual(report["formalAcceptanceLedgerGitBlob"], batch.V5_GIT_BLOB)
            self.assertEqual(report["batchDecisions"]["BLOCKED"], 64)
            self.assertEqual(report["batchDecisions"]["ALREADY_ACCEPTED"], 6)
            self.assertEqual(report["batchDecisions"]["PASS_CANDIDATE"], 0)
            self.assertFalse(report["publicationAuthorized"])
            self.assertTrue((Path(d) / "rows" / "summary.json").is_file())

    def test_historical_checksum_profile_is_exact_identity_only(self):
        p = {"id": 408449466, "tag_name": "v1.2-20250903-windows.2",
             "target_commitish": batch.HISTORICAL_PG14_PIN["packaging"]}
        self.assertEqual(batch.original_profile("pg_bigm", p),
                         "historical-pg_bigm-original-checksums/v1")
        self.assertEqual(batch.original_profile("orafce", p), "main-promotion/v1")
        self.assertEqual(batch.original_profile("pg_bigm", dict(p, id=999)),
                         "main-promotion/v1")
        for mutation in ({"tag_name": "different"},
                         {"target_commitish": "a" * 40}):
            with self.assertRaises(Denied):
                batch.original_profile("pg_bigm", dict(p, **mutation))

    def test_genuine_original_zip_crc_and_untrusted_profile_observation(self):
        import zipfile
        def fixtures(directory, attack=None):
            rows = {}
            for major in range(14, 19):
                stem = f"test-pg{major}"
                zname = stem + ".zip"
                spdx = stem + ".spdx.json"
                grype = stem + ".vulnerabilities.json"
                info = {
                    "schemaVersion": 1,
                    "package": {"name": "hypopg", "platform": "windows", "architecture": "x64"},
                    "postgresql": {"major": major},
                    "workflowRun": {"id": 123, "attempt": 1, "event": "push",
                                    "ref": "refs/heads/release/legacy"},
                    "upstream": {"ref": "v1", "commit": "a" * 40},
                    "source": {"packagingCommit": "b" * 40},
                    "buildInfrastructure": {"commit": "c" * 40},
                }
                if attack == "wrong-pg" and major == 15:
                    info["postgresql"]["major"] = 18
                with zipfile.ZipFile(directory / zname, "w") as zf:
                    zf.writestr("PACKAGE-INFO.json", json.dumps(info))
                    zf.writestr("../escape" if attack == "zip-slip" and major == 15
                                else "lib/test.dll", b"data")
                (directory / spdx).write_text(
                    json.dumps({"spdxVersion": "SPDX-2.3" if attack != "spdx" or major != 15
                                else "BAD"}))
                (directory / grype).write_text(json.dumps({"matches": []}))
                rows[str(major)] = {
                    "available": True, "asset": zname,
                    "evidence": {"sbom": {"asset": spdx},
                                 "vulnerabilityReport": {"asset": grype}},
                }
            return {"postgresql": rows}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = fixtures(root)
            run = {"id": 123, "run_attempt": 1, "path": ".github/workflows/windows.yml",
                   "event": "push", "head_branch": "release/legacy",
                   "head_sha": "b" * 40, "conclusion": "success", "status": "completed",
                   "repository": {"id": 123}}
            with patch.object(batch, "api_json", return_value=run):
                output = batch.inspect_release_structure(root, record, "hypopg", {})
            self.assertEqual(len(output), 5)
            self.assertEqual(output["15"]["githubRun"]["workflow"],
                             ".github/workflows/windows.yml")
            self.assertEqual(output["15"]["profileStatus"], "UNVERIFIED_OBSERVATION_ONLY")
        for attack in ("wrong-pg", "zip-slip", "spdx"):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                record = fixtures(root, attack)
                with patch.object(batch, "api_json") as api:
                    with self.subTest(attack=attack), self.assertRaises(Denied):
                        batch.inspect_release_structure(root, record, "hypopg", {})
                    self.assertLessEqual(api.call_count, 1)  # PG14 precedes hostile PG15

    def test_original_pinned_checksum_spellings_are_strict_and_signed_profile_unchanged(self):
        pinned = {f"asset-{i}.zip" for i in range(15)}
        d = "a" * 64
        canonical = ("".join(d + "  " + n + "\n" for n in sorted(pinned))).encode()
        dotted = ("".join(d + "  ./" + n + "\n" for n in sorted(pinned))).encode()
        self.assertEqual(set(batch.parse_pinned_original_sums(canonical, pinned)), pinned)
        self.assertEqual(set(batch.parse_pinned_original_sums(dotted, pinned)), pinned)
        for bad in (
            dotted.replace(b"./", b"", 1),
            dotted.replace(b"./", b"../", 1),
            dotted.replace(b"./", b".//", 1),
            dotted.replace(b"asset-0", b"asset-1", 1),
            dotted.replace(b"asset-0", b"ASSET-0", 1),
            dotted[:-10],
        ):
            with self.subTest(bad=bad[:80]), self.assertRaises(Denied):
                batch.parse_pinned_original_sums(bad, pinned)

    def test_historical_sums_alias_rejects_wrong_layout(self):
        pinned = {f"sample-{i}.zip" for i in range(15)}
        digest = "a" * 64
        original = ("".join(digest + "  ./" + n + "\n"
                            for n in sorted(pinned))).encode("ascii")
        self.assertEqual(
            set(batch.parse_original_historical_sums(original, pinned)), pinned)
        for attack in (original.replace(b"./", b"../", 1),
                       original.replace(b"./", b"", 1),
                       original.replace(b"./", b".//", 1),
                       original.replace(b"sample-0", b"sample-1", 1)):
            with self.assertRaises(Denied):
                batch.parse_original_historical_sums(attack, pinned)

    def test_immutable_catalog_pins_match_exact_repository_files(self):
        root = Path(__file__).resolve().parents[1]
        policy = json.loads((root / "config" / "issue112-p1-fleet-pins-20261017.json").read_text())
        self.assertEqual(policy["catalogCommitSha"],
                         "e372e2c6a95adcf8227ea82d6253df3792b6f029")
        self.assertEqual(set(policy["repoIds"]), set(batch.NAMES))
        self.assertEqual(set(policy["releaseIds"]), set(batch.NAMES))
        self.assertEqual(set(policy["assetIds"]), set(batch.NAMES))
        self.assertEqual(sum(map(len, policy["assetIds"].values())), 224)
        import hashlib
        for name, expected_hash in policy["catalogDigests"].items():
            with self.subTest(path=name):
                self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(),
                                 expected_hash)

    def test_no_unknown_pg_or_missing_policy(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Denied):
                batch.run(self.policy, Path(d) / "cache", Path(d) / "report")
            self.assertNotIn("19", batch.MAJORS)
            self.assertEqual(len(batch.NAMES) * len(batch.MAJORS), 70)

    def test_previous_pg14_row_does_not_count_twice(self):
        p = dict(self.policy)
        p["assetIds"] = {"pg_bigm": {}}
        release = {"target_commitish": "d" * 40, "assets": [
            {"id": 626562095,
             "name": "pg_bigm-v1.2-pg14-windows-x64.zip", "size": 1,
             "digest": "sha256:" + "a" * 64}
        ]}
        key = batch.identity(p, "pg_bigm", release)
        result = batch.row_receipt("pg_bigm", "14", p, release, key, {}, {
            "decision": "ALREADY_ACCEPTED", "reason": "sealed previously"})
        self.assertIs(result["formalAcceptedByThisRun"], False)
        self.assertIs(result["signatureVerified"], False)
        self.assertIs(result["publicationAuthorized"], False)
        self.assertNotEqual(result["decision"], "PASS_CANDIDATE")

    def test_fail_closed_bad_run_jobs_without_running_online(self):
        example = {"jobs": [
            {"name": "Build / PostgreSQL 15 / Windows x64", "conclusion": "failure", "id": 1},
            {"name": "Verify signatures and SHA; create-only formal publication",
             "conclusion": "success", "id": 2}
        ], "total_count": 2}
        proc = type("P", (), {"returncode": 0, "stdout": json.dumps(example).encode()})()
        with patch.object(batch.subprocess, "run", return_value=proc):
            with self.assertRaises(Denied):
                batch.fetch_jobs("plpgsql_check", 38128142145, "15")
            with self.assertRaises(Denied):
                batch.fetch_jobs("plpgsql_check", 38128142145, "18")
            with self.assertRaises(Denied):
                batch.fetch_jobs("../evil", 1, "15")
        example["jobs"][0]["conclusion"] = "success"
        example["total_count"] = 3
        proc.stdout = json.dumps(example).encode()
        with patch.object(batch.subprocess, "run", return_value=proc):
            with self.assertRaises(Denied):
                batch.fetch_jobs("plpgsql_check", 123, "15")

    def test_wal2json_proven_real_publish_job_name_requires_success(self):
        jobs = [
            {"id": 114748851643, "name":
             "Rebuild signed Windows x64 binary and SBOM from verified current main / PostgreSQL 15 / Windows x64",
             "conclusion": "success"},
            {"id": 114753316427,
             "name": "Check signatures, exact SHA256 and create-only Release ID",
             "conclusion": "success"}
        ]
        p = type("Proc", (), {"returncode": 0,
                              "stdout": json.dumps({"jobs": jobs, "total_count": 2}).encode()})()
        with patch.object(batch.subprocess, "run", return_value=p):
            a = batch.fetch_jobs("wal2json", 38230537748, "15")
            self.assertEqual(a["publicationJobId"], 114753316427)
            self.assertEqual(a["buildJobId"], 114748851643)
        jobs[1]["conclusion"] = "failure"
        p.stdout = json.dumps({"jobs": jobs, "total_count": 2}).encode()
        with patch.object(batch.subprocess, "run", return_value=p):
            with self.assertRaises(Denied):
                batch.fetch_jobs("wal2json", 38230537748, "15")
        jobs[1]["conclusion"] = "success"
        jobs[1]["name"] = "Any other publisher success"
        p.stdout = json.dumps({"jobs": jobs, "total_count": 2}).encode()
        with patch.object(batch.subprocess, "run", return_value=p):
            with self.assertRaises(Denied):
                batch.fetch_jobs("wal2json", 38230537748, "15")

    def test_successor_builder_full_sha_is_explicit_not_automatic(self):
        root = Path(__file__).resolve().parents[1]
        policy = json.loads((root / "config/issue112-p1-fleet-pins-20261017.json").read_text())
        self.assertEqual(
            set(policy["trustedSignerShas"]),
            {"8246f4d3415a48b1ad4af13f421277057886b58f",
             "5756b3c5136a8bf4db710016cfe97555f0a71c6d"})
        self.assertEqual(policy["signerEvidence"]["wal2jsonSourceCommit"],
                         "1198ff30137ee3fd01a9e168647a7167324bb713")

    def test_root_swap_or_tuf_error_not_signature_verified(self):
        with tempfile.TemporaryDirectory() as d:
            p = type("P", (), {"returncode": 0, "stdout": b"not-matching-root"})()
            with patch.object(batch.subprocess, "run", return_value=p):
                with self.assertRaises(Denied):
                    batch.fresh_root(self.policy, Path(d) / "root")
            p.returncode = 1
            with patch.object(batch.subprocess, "run", return_value=p):
                with self.assertRaises(Denied):
                    batch.fresh_root(self.policy, Path(d) / "root")

    def test_no_gh_provenance_is_denied(self):
        with patch.object(batch.shutil, "which", return_value=None):
            with self.assertRaises(Denied):
                batch.require_gh(self.policy)

    def test_readonly_runner_disallows_publisher_and_status_escalation(self):
        source = Path(batch.__file__).read_text()
        for forbidden in ("gh release create", "gh workflow run", "workflow_dispatch(",
                          "publicationAuthorized\": True", "distributionAuthorized\": True",
                          "create_release(", "merge_pull_request("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
