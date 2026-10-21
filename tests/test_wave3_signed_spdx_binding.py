#!/usr/bin/env python3
"""Wave3 Catalog: actual gh signer pin + signed public SPDX binding (offline).

Mocks model structurally plausible gh output only; they are NOT cryptographic
attestations or permission to publish. No GitHub network or Release writes.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import verify_signed_fleet_release as verifier


class Wave3SignedSpdxBinding(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.zip = root / "pgtap-v1.3.4-pg14-windows-x64.zip"
        self.zip.write_bytes(b"synthetic-not-a-valid-windows-zip")
        self.spdx = root / "pgtap-v1.3.4-pg14-windows-x64.spdx.json"
        self.document = {
            "spdxVersion": "SPDX-2.3",
            "name": "synthetic-first-release",
            "packages": [{"SPDXID": "SPDXRef-Test"}],
        }
        self.spdx.write_text(json.dumps(self.document), encoding="utf-8")
        self.commit = "a" * 40
        self.repo = "pgextwin/pgtap"
        self.digest = verifier.digest(self.zip)

    def attested(self, predicate, *, document=None, filename=None, sha=None):
        return [{
            "verificationResult": {
                "statement": {
                    "predicateType": predicate,
                    "subject": [{
                        "name": filename if filename is not None else self.zip.name,
                        "digest": {"sha256": sha if sha is not None else self.digest},
                    }],
                    "predicate": copy.deepcopy(
                        document if document is not None else
                        self.document if predicate == verifier.SPDX else
                        {"buildDefinition": {"buildType": "synthetic"}}),
                },
                "signature": {"certificate": {"issuer": "synthetic"}},
            },
        }]

    def signed_output(self, *args):
        self.assertEqual(args[:2], ("attestation", "verify"))
        self.assertEqual(args[2], str(self.zip))
        self.assertEqual(args[args.index("--repo") + 1], self.repo)
        self.assertEqual(args[args.index("--signer-workflow") + 1], verifier.SIGNER)
        self.assertEqual(args[args.index("--signer-digest") + 1],
                         verifier.WAVE3_SIGNER_SHA)
        self.assertEqual(args[args.index("--source-digest") + 1], self.commit)
        self.assertEqual(args[args.index("--source-ref") + 1], "refs/heads/main")
        self.assertEqual(args[args.index("--format") + 1], "json")
        predicate = args[args.index("--predicate-type") + 1]
        return json.dumps(self.attested(predicate))

    def test_all_first_release_identities_use_pinned_claims(self):
        self.assertEqual(set(verifier.FIRST_RELEASE_SOURCES),
                         {"pgtap", "pg_variables", "pg_store_plans"})
        for extension in sorted(verifier.FIRST_RELEASE_SOURCES):
            with self.subTest(extension=extension):
                self.repo = "pgextwin/" + extension
                with patch.object(verifier, "gh", side_effect=self.signed_output) as gh:
                    verifier.verify_wave3_attestations(
                        self.zip, self.spdx, repo=self.repo,
                        source_commit=self.commit)
                self.assertEqual(gh.call_count, 2)
                self.assertEqual(
                    [x.args[x.args.index("--predicate-type") + 1]
                     for x in gh.call_args_list],
                    [verifier.PROVENANCE, verifier.SPDX])

    def test_signed_spdx_must_equal_published_file_even_when_hashes_match(self):
        changed = copy.deepcopy(self.document)
        changed["packages"][0]["SPDXID"] = "SPDXRef-Forged"
        data = json.dumps(self.attested(verifier.SPDX, document=changed))
        with self.assertRaises(verifier.Denied):
            verifier.validate_wave3_verified_attestation(
                data, predicate=verifier.SPDX, zip_name=self.zip.name,
                zip_sha=self.digest, expected_spdx=self.document)

    def test_unsigned_or_ambiguous_claim_fails_closed(self):
        for predicate in (verifier.PROVENANCE, verifier.SPDX):
            correct = self.attested(predicate)
            examples = [
                [],
                correct + correct,
                {},
                [{"verificationResult": {"statement": None}}],
                self.attested(predicate, filename="other.zip"),
                self.attested(predicate, sha="0" * 64),
                self.attested("https://untrusted.example/fake"),
                [{"verificationResult": {"statement": {
                    "predicateType": predicate,
                    "subject": correct[0]["verificationResult"]["statement"]["subject"]
                    + correct[0]["verificationResult"]["statement"]["subject"],
                    "predicate": self.document,
                }}}],
            ]
            if predicate == verifier.PROVENANCE:
                missing = copy.deepcopy(correct)
                missing[0]["verificationResult"]["statement"]["predicate"] = "invalid"
                examples.append(missing)
            else:
                wrong = copy.deepcopy(correct)
                wrong[0]["verificationResult"]["statement"]["predicate"]["name"] = "altered"
                examples.append(wrong)
            for variant in examples:
                with self.subTest(predicate=predicate, example=str(variant)[:80]):
                    with self.assertRaises(verifier.Denied):
                        verifier.validate_wave3_verified_attestation(
                            json.dumps(variant), predicate=predicate,
                            zip_name=self.zip.name, zip_sha=self.digest,
                            expected_spdx=self.document)
        duplicate_json = (
            '[{"verificationResult":{"statement":{"predicateType":"'
            + verifier.SPDX + '","predicateType":"' + verifier.SPDX + '"}}}]'
        )
        with self.assertRaises(verifier.Denied):
            verifier.validate_wave3_verified_attestation(
                duplicate_json, predicate=verifier.SPDX,
                zip_name=self.zip.name, zip_sha=self.digest,
                expected_spdx=self.document)

    def test_reject_wrong_repository_commit_and_spdx(self):
        for repo, sha in (("pgextwin/wal2json", self.commit),
                          ("pgextwin/pgtap", "other"),
                          ("pgextwin/evil", self.commit)):
            with self.subTest(repo=repo, commit=sha):
                with patch.object(verifier, "gh") as gh:
                    with self.assertRaises(verifier.Denied):
                        verifier.verify_wave3_attestations(
                            self.zip, self.spdx, repo=repo, source_commit=sha)
                    gh.assert_not_called()
        self.spdx.write_text('{"spdxVersion":"SPDX-2.3","spdxVersion":"SPDX-2.3"}')
        with patch.object(verifier, "gh") as gh:
            with self.assertRaises(verifier.Denied):
                verifier.verify_wave3_attestations(
                    self.zip, self.spdx, repo=self.repo, source_commit=self.commit)
            gh.assert_not_called()

    def test_mutation_during_attestation_rejected(self):
        def mutate_after_gh(*args):
            if "--predicate-type" in args and args[
                    args.index("--predicate-type") + 1] == verifier.PROVENANCE:
                self.spdx.write_text(json.dumps({"spdxVersion": "SPDX-2.3",
                                                   "name": "changed"}))
            return self.signed_output(*args)
        with patch.object(verifier, "gh", side_effect=mutate_after_gh):
            with self.assertRaises(verifier.Denied):
                verifier.verify_wave3_attestations(
                    self.zip, self.spdx, repo=self.repo, source_commit=self.commit)

    def test_gh_verification_error_is_not_a_signed_release(self):
        with patch.object(verifier, "gh", side_effect=verifier.Denied("403")):
            with self.assertRaises(verifier.Denied):
                verifier.verify_wave3_attestations(
                    self.zip, self.spdx, repo=self.repo, source_commit=self.commit)

    def test_historical_fourteen_intake_stays_unchanged(self):
        script = (Path(__file__).resolve().parents[1] /
                  "scripts/verify_signed_fleet_release.py").read_text()
        self.assertIn("if extension in FIRST_RELEASE_SOURCES:", script)
        self.assertIn("Historical 14-member intake contract is unchanged.", script)
        self.assertIn('gh("attestation", "verify", zipped, "--repo", repo,', script)
        self.assertIn('verify_main_run(repo, run_id, source_commit)', script)
        self.assertLess(script.index("verify_main_run(repo, run_id, source_commit)"),
                        script.index("if extension in FIRST_RELEASE_SOURCES:"))


if __name__ == "__main__":
    unittest.main()
