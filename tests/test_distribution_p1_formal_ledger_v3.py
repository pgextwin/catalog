#!/usr/bin/env python3
"""Hostile v3 formal acceptance tests; NEVER synthetic Sigstore success."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from distribution_manifest_v1 import Denied
import distribution_p1_formal_ledger_v3 as v3


class ImmutableFormalIntakeTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(v3.LEDGER.read_text(encoding="utf-8"))
        self.previous = v3.PREVIOUS.read_bytes()

    def verify(self, doc=None, previous=None):
        data = json.dumps(self.document if doc is None else doc).encode("utf-8")
        return v3.validate(data, self.previous if previous is None else previous)

    def test_real_five_row_receipt_identity_v3_record_only(self):
        result = self.verify()
        self.assertEqual(result["accepted"], 6)
        self.assertEqual(result["historicalSourceAccepted"], 0)
        self.assertEqual(result["decision"], "V3_RECORD_INTEGRITY_VALID_NOT_A_CRYPTO_TEST")
        self.assertIs(result["publicationAuthorized"], False)

    def test_denies_duplicate_row_or_identity_replay(self):
        for i in range(1, 6):
            a = copy.deepcopy(self.document)
            a["acceptedRows"][i] = copy.deepcopy(a["acceptedRows"][0])
            with self.subTest(i=i), self.assertRaises(Denied):
                self.verify(a)
        a = copy.deepcopy(self.document)
        a["acceptedRows"].append(copy.deepcopy(a["acceptedRows"][1]))
        a["formalP1Accepted"] = 7
        with self.assertRaises(Denied):
            self.verify(a)

    def test_denies_tampered_sigstore_signer_bundle_and_source(self):
        for key, value in (
            ("pgMajor", 19), ("assetId", 633345012),
            ("originalZipSha256", "a"*64),
            ("rowReceiptSha256", "0"*64),
            ("bundleSha256", "1"*64),
            ("trustedRootSha256", "f"*64),
            ("signerSha", "f"*40),
            ("runId", 38128142145),
            ("runAttempt", 2),
            ("publisherJobId", 114748851610),
            ("buildJobId", 0),
            ("releaseId", 408449466),
            ("profile", "historical-pg_bigm-pg14/1"),
            ("sourceVerified", False),
            ("signatureVerified", False),
            ("integrityVerified", False),
            ("runAndJobsVerified", False),
            ("verificationOrigin", "mocked"),
            ("workIndividualAuditRequired", True),
        ):
            a = copy.deepcopy(self.document)
            a["acceptedRows"][1][key] = value
            with self.subTest(field=key), self.assertRaises(Denied):
                self.verify(a)

    def test_denies_wrong_original_release_evidence_or_ci_replay(self):
        for key, value in (
            ("auditRunId", 1), ("auditMainCommit", "a"*40),
            ("artifactSha256", "a"*64), ("commonReceiptSha256", "a"*64),
            ("summaryReceiptSha256", "a"*64), ("artifactId", 1),
            ("fullReleaseAssetsRehashed", False), ("allPgZipCrcVerified", False),
            ("allSpdxGrypeInspected", False),
            ("checksPerformedWithRealGhAndTuf", False),
            ("originalReleaseAssetsAreNotActionsArtifacts", False),
        ):
            a = copy.deepcopy(self.document)
            a["acceptedRows"][1]["evidence"][key] = value
            with self.subTest(field=key), self.assertRaises(Denied):
                self.verify(a)

    def test_denies_false_publication_or_source_counts(self):
        for key, value in (
            ("formalP1Accepted", 70), ("unacceptedRows", 0),
            ("historicalSourceAccepted", 5),
            ("historicalSourceAcceptedRows", [{"extension": "wal2json", "pgMajor": 15}]),
            ("fleetComplete", True), ("p1", "PASS"), ("p2", "GO"),
            ("publicationAuthorized", True), ("distributionAuthorized", True),
            ("formalDistribution", "ALLOW"),
        ):
            a = copy.deepcopy(self.document)
            a[key] = value
            with self.subTest(field=key), self.assertRaises(Denied):
                self.verify(a)

    def test_previous_sealed_ledger_cannot_change(self):
        bad = self.previous.replace(b'"formalP1Accepted": 1',
                                    b'"formalP1Accepted": 2')
        with self.assertRaises(Denied):
            self.verify(previous=bad)

    def test_duplicate_json_keys_fail_closed(self):
        text = v3.LEDGER.read_bytes()
        self.assertIn(b'"formalP1Accepted": 6', text)
        data = text.replace(b'"formalP1Accepted": 6',
                            b'"formalP1Accepted": 6, "formalP1Accepted": 70')
        with self.assertRaises(Denied):
            v3.validate(data, self.previous)


if __name__ == "__main__":
    unittest.main()
