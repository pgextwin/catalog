#!/usr/bin/env python3
"""17-extension Catalog signed Release parity and hostile regression fixtures.

Synthetic gh responses are parser/argument tests only; zero live cryptographic
proof, signer custody, formal publication or permission changes.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from scripts import verified_release_record
from scripts import verify_signed_fleet_release as verifier


class SignedReleaseEvidenceParity(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)
        self.repo = "pgextwin/pgtap"
        self.commit = "a" * 40
        self.signer = verifier.FIRST_RELEASE_SIGNER_SHA
        self.document = {
            "spdxVersion": "SPDX-2.3",
            "name": "synthetic-signed-release",
            "packages": [{"SPDXID": "SPDXRef-Test"}],
        }
        self.prepare("pgtap")

    def prepare(self, extension, *, signer=None):
        self.repo = "pgextwin/" + extension
        self.signer = signer or verifier.FIRST_RELEASE_SIGNER_SHA
        stem = extension + "-v1.2.3-pg14-windows-x64"
        self.zip = self.directory / (stem + ".zip")
        self.spdx = self.directory / (stem + ".spdx.json")
        pkg = {"schemaVersion": 1,
               "buildInfrastructure": {
                   "repository": "pgextwin/build",
                   "commit": self.signer,
                   "workflow": ".github/workflows/build-extension-attested.yml"}}
        with ZipFile(self.zip, "w") as archive:
            archive.writestr("PACKAGE-INFO.json", json.dumps(pkg))
        self.spdx.write_text(json.dumps(self.document), encoding="utf-8")
        self.digest = verifier.digest(self.zip)

    def attested(self, predicate, *, signed_spdx=None, zip_name=None, zip_sha=None):
        return [{
            "verificationResult": {
                "statement": {
                    "predicateType": predicate,
                    "subject": [{
                        "name": zip_name if zip_name is not None else self.zip.name,
                        "digest": {"sha256": zip_sha if zip_sha is not None
                                   else self.digest}}],
                    "predicate": copy.deepcopy(
                        signed_spdx if signed_spdx is not None else
                        self.document if predicate == verifier.SPDX else
                        {"buildDefinition": {"buildType": "synthetic"}}),
                },
                "signature": {"certificate": {"issuer": "synthetic"}},
            },
        }]

    def signed_output(self, *args):
        self.assertEqual(args[:2], ("attestation", "verify"))
        self.assertEqual(args[2], str(self.zip))
        required = {
            "--repo": self.repo,
            "--signer-workflow": verifier.SIGNER,
            "--signer-digest": self.signer,
            "--source-digest": self.commit,
            "--source-ref": "refs/heads/main",
            "--format": "json",
        }
        for flag, value in required.items():
            self.assertIn(flag, args)
            self.assertEqual(args[args.index(flag) + 1], value)
        predicate = args[args.index("--predicate-type") + 1]
        self.assertIn(predicate, (verifier.PROVENANCE, verifier.SPDX))
        return json.dumps(self.attested(predicate))

    def test_all_seventeen_use_exact_two_signed_predicates(self):
        self.assertEqual(len(verifier.INTAKE_ALLOWED), 17)
        self.assertEqual(set(verifier.INTAKE_ALLOWED),
                         set(verified_release_record.ALLOWED)
                         | set(verified_release_record.FIRST_RELEASE_SOURCES))
        for extension in sorted(verifier.INTAKE_ALLOWED):
            with self.subTest(extension=extension):
                # Historical Signer commits are not rewritten to the Wave3 pin.
                historic = extension not in verifier.FIRST_RELEASE_SOURCES
                sha = ("b" * 40) if historic else verifier.FIRST_RELEASE_SIGNER_SHA
                self.prepare(extension, signer=sha)
                with patch.object(verifier, "gh",
                                  side_effect=self.signed_output) as gh:
                    result = verifier.verify_release_attestations(
                        self.zip, self.spdx, repo=self.repo,
                        source_commit=self.commit)
                self.assertEqual(result, sha)
                self.assertEqual(gh.call_count, 2)
                self.assertEqual(
                    [c.args[c.args.index("--predicate-type") + 1]
                     for c in gh.call_args_list],
                    [verifier.PROVENANCE, verifier.SPDX])

    def test_wider_signer_compatibility_only_for_historical_fourteen(self):
        self.prepare("hypopg", signer="c" * 40)
        with patch.object(verifier, "gh",
                          side_effect=self.signed_output) as gh:
            self.assertEqual(
                verifier.verify_release_attestations(
                    self.zip, self.spdx, repo=self.repo,
                    source_commit=self.commit), "c" * 40)
            self.assertEqual(gh.call_count, 2)
        self.prepare("pgtap", signer="c" * 40)
        with patch.object(verifier, "gh") as gh:
            with self.assertRaises(verifier.Denied):
                verifier.verify_release_attestations(
                    self.zip, self.spdx, repo=self.repo,
                    source_commit=self.commit)
            gh.assert_not_called()

    def test_signed_spdx_must_equal_public_file_even_if_all_hashes_match(self):
        wrong = copy.deepcopy(self.document)
        wrong["packages"][0]["SPDXID"] = "SPDXRef-Incorrect"
        claim = json.dumps(self.attested(verifier.SPDX, signed_spdx=wrong))
        with self.assertRaises(verifier.Denied):
            verifier.validate_verified_attestation(
                claim, predicate=verifier.SPDX, zip_name=self.zip.name,
                zip_sha=self.digest, expected_spdx=self.document)

    def test_duplicate_ambiguous_missing_or_cross_subject_proofs_denied(self):
        for predicate in (verifier.PROVENANCE, verifier.SPDX):
            valid = self.attested(predicate)
            bad = [
                [], valid + valid, {}, {"verificationResult": {}},
                self.attested(predicate, zip_name="forged.zip"),
                self.attested(predicate, zip_sha="0" * 64),
                self.attested("https://example.invalid/forgery"),
                [{"verificationResult": {"statement": {
                    "predicateType": predicate,
                    "subject": valid[0]["verificationResult"]["statement"]["subject"] * 2,
                    "predicate": self.document,
                }}}],
            ]
            if predicate == verifier.PROVENANCE:
                tampered = copy.deepcopy(valid)
                tampered[0]["verificationResult"]["statement"]["predicate"] = "bad"
            else:
                tampered = copy.deepcopy(valid)
                tampered[0]["verificationResult"]["statement"]["predicate"]["name"] = "forged"
            bad.append(tampered)
            for value in bad:
                with self.subTest(predicate=predicate, bad=str(value)[:70]):
                    with self.assertRaises(verifier.Denied):
                        verifier.validate_verified_attestation(
                            json.dumps(value), predicate=predicate,
                            zip_name=self.zip.name, zip_sha=self.digest,
                            expected_spdx=self.document)
        duplicate = (
            '[{"verificationResult":{"statement":{"predicateType":"'
            + verifier.SPDX + '","predicateType":"' + verifier.SPDX + '"}}}]'
        )
        with self.assertRaises(verifier.Denied):
            verifier.validate_verified_attestation(
                duplicate, predicate=verifier.SPDX, zip_name=self.zip.name,
                zip_sha=self.digest, expected_spdx=self.document)

    def test_bad_repo_source_unauthorized_signer_and_spdx_denied_pre_cli(self):
        for repo, sha in (("pgextwin/other", self.commit),
                          (self.repo, "not-a-commit"),
                          ("foreign/pgtap", self.commit)):
            with self.subTest(repo=repo, sha=sha):
                with patch.object(verifier, "gh") as gh:
                    with self.assertRaises(verifier.Denied):
                        verifier.verify_release_attestations(
                            self.zip, self.spdx, repo=repo, source_commit=sha)
                    gh.assert_not_called()
        self.spdx.write_text(
            '{"spdxVersion":"SPDX-2.3","spdxVersion":"SPDX-2.3"}')
        with patch.object(verifier, "gh") as gh:
            with self.assertRaises(verifier.Denied):
                verifier.verify_release_attestations(
                    self.zip, self.spdx, repo=self.repo,
                    source_commit=self.commit)
            gh.assert_not_called()

    def test_cross_major_wrong_signer_metadata_rejected(self):
        self.prepare("orafce", signer="b" * 40)
        self.assertEqual(
            verifier.signer_sha_from_package(self.zip, self.repo), "b" * 40)
        for changed in (
            {"repository": "attacker/build", "commit": "b" * 40,
             "workflow": ".github/workflows/build-extension-attested.yml"},
            {"repository": "pgextwin/build", "commit": "not-a-commit",
             "workflow": ".github/workflows/build-extension-attested.yml"},
            {"repository": "pgextwin/build", "commit": "b" * 40,
             "workflow": ".github/workflows/evil.yml"},
        ):
            with self.subTest(changed=changed):
                with ZipFile(self.zip, "w") as archive:
                    archive.writestr("PACKAGE-INFO.json", json.dumps({
                        "schemaVersion": 1, "buildInfrastructure": changed}))
                with self.assertRaises(verifier.Denied):
                    verifier.signer_sha_from_package(self.zip, self.repo)

    def test_mutation_during_attestation_denied(self):
        def mutate(*args):
            if args[args.index("--predicate-type") + 1] == verifier.PROVENANCE:
                self.spdx.write_text(
                    json.dumps({"spdxVersion": "SPDX-2.3", "name": "changed"}))
            return self.signed_output(*args)
        with patch.object(verifier, "gh", side_effect=mutate):
            with self.assertRaises(verifier.Denied):
                verifier.verify_release_attestations(
                    self.zip, self.spdx, repo=self.repo,
                    source_commit=self.commit)

    def test_gh_error_and_zero_mock_trust_never_authorize_release(self):
        with patch.object(verifier, "gh", side_effect=verifier.Denied("403")):
            with self.assertRaises(verifier.Denied):
                verifier.verify_release_attestations(
                    self.zip, self.spdx, repo=self.repo,
                    source_commit=self.commit)

    def test_one_uniform_verifier_in_actual_catalog_ingestion(self):
        source = (Path(__file__).resolve().parents[1] /
                  "scripts/verify_signed_fleet_release.py").read_text()
        self.assertIn("actual_sha = verify_release_attestations(", source)
        self.assertIn("signer_sha == actual_sha", source)
        self.assertNotIn("if extension in FIRST_RELEASE_SOURCES:\n                verify_release_attestations", source)
        self.assertIn("verify_main_run(repo, run_id, source_commit)", source)
        self.assertLess(
            source.index("verify_main_run(repo, run_id, source_commit)"),
            source.index("actual_sha = verify_release_attestations("))


if __name__ == "__main__":
    unittest.main()
