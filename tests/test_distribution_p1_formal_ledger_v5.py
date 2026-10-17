#!/usr/bin/env python3
"""Hostile immutable v5 intake tests; NEVER simulated Sigstore as true PASS."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from distribution_manifest_v1 import Denied
import distribution_p1_formal_ledger_v5 as v5


class StrictOrafceFormalV5(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = v5.V5.read_bytes()
        cls.doc = json.loads(cls.raw)
        cls.prev = v5.V4.read_bytes()
        cls.pins = v5.PINS.read_bytes()
        cls.fleet = v5.FLEET.read_bytes()

    def check(self, raw=None, prev=None, pins=None, fleet=None):
        return v5.validate(
            self.raw if raw is None else raw,
            self.prev if prev is None else prev,
            self.pins if pins is None else pins,
            self.fleet if fleet is None else fleet)

    def forged(self, doc, *, bypass_outer_blob=True):
        raw = json.dumps(doc, ensure_ascii=False).encode()
        if bypass_outer_blob:
            with patch.object(v5, "V5_GIT_BLOB", v5.git_blob(raw)):
                with self.assertRaises(Denied):
                    self.check(raw=raw)
        else:
            with self.assertRaises(Denied):
                self.check(raw=raw)

    def test_exact_four_actual_genuine_receipts_and_65_not_distribution(self):
        result = self.check()
        self.assertEqual(result["accepted"], 65)
        self.assertEqual(result["addedGenuineRows"], 4)
        self.assertEqual(result["remainingDenied"], 5)
        self.assertEqual(result["historicalSourceAccepted"], 0)
        self.assertFalse(result["publicationAuthorized"])
        self.assertFalse(result["distributionAuthorized"])
        self.assertIn("NOT_A_CRYPTO_TEST", result["decision"])

    def test_change_previous_61_row_ledger_or_pin_denied(self):
        with self.assertRaises(Denied):
            self.check(prev=self.prev.replace(b'"formalP1Accepted": 61',
                                              b'"formalP1Accepted": 62'))
        with self.assertRaises(Denied):
            self.check(pins=self.pins.replace(b'"runAttempt": 2',
                                              b'"runAttempt": 1'))

    def test_bypass_outer_hash_does_not_allow_fake_release_signature_or_attempt(self):
        bad_fields = (
            ("extension", "plpgsql_check"), ("pgMajor", 18),
            ("repositoryId", 1), ("releaseId", 1),
            ("assetId", 628346168), ("assetName", "orafce-pg18-windows-x64.zip"),
            ("originalZipSha256", "a" * 64),
            ("originalArtifactTransferSha256", "b" * 64),
            ("bundleSha256", "c" * 64),
            ("rowReceiptSha256", "d" * 64),
            ("originalBuildJobId", 114244899826),
            ("originalBuildAttempt", 2),
            ("originalRunAttempt1Conclusion", "success"),
            ("finalPublicationAttempt", 1),
            ("finalRunAttempt2Conclusion", "failure"),
            ("finalPublishJobId", 114247455038),
            ("packagingSha", "f" * 40),
            ("signerSha", "f" * 40),
            ("runId", 38128142145),
            ("profile", "historical-pg_bigm-pg14/1"),
            ("workIndividualAuditRequired", True),
        )
        for field, value in bad_fields:
            with self.subTest(field=field):
                d = copy.deepcopy(self.doc)
                d["newAcceptedRows"][0][field] = value
                self.forged(d)

    def test_duplicate_v4_or_v5_admission_denied(self):
        for replacement in (
            copy.deepcopy(self.doc["newAcceptedRows"][0]),
            dict(self.doc["newAcceptedRows"][0], pgMajor=18),
            dict(self.doc["newAcceptedRows"][0], extension="wal2json"),
            dict(self.doc["newAcceptedRows"][0], extension="orafce", pgMajor=15),
        ):
            d = copy.deepcopy(self.doc)
            d["newAcceptedRows"][-1] = replacement
            self.forged(d)

    def test_fail_closed_gate_and_audit_tampering(self):
        cases = {
            "previousFormalAccepted": 6, "newAcceptedCount": 5,
            "formalP1Accepted": 70, "remainingDenied": 0,
            "historicalSourceAccepted": 40,
            "plpgsqlCheckFailedOriginalRunUnwaived": False,
            "orafceOriginalAttempt1RunIsFailure": False,
            "orafceOriginalAttempt2PublishSuccess": False,
            "fleetComplete": True, "p1": "PASS", "p2": "GO",
            "publicationAuthorized": True, "distributionAuthorized": True,
            "formalDistribution": "ALLOW",
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                d = copy.deepcopy(self.doc)
                d[field] = value
                self.forged(d)
        for field, value in (
            ("runConclusion", "success"),
            ("actualBatchExitCode", 0),
            ("diagnosticArtifactSha256", "0" * 64),
            ("summaryJsonSha256", "0" * 64),
            ("orafceGenuineTufAndDualSigstorePerRow", False),
        ):
            with self.subTest(audit=field):
                d = copy.deepcopy(self.doc)
                d["audit"][field] = value
                self.forged(d)

    def test_duplicate_json_key_is_denied_even_if_blob_hash_repinned(self):
        raw = self.raw.replace(
            b'"formalP1Accepted": 65',
            b'"formalP1Accepted": 65, "formalP1Accepted": 70')
        with patch.object(v5, "V5_GIT_BLOB", v5.git_blob(raw)):
            with self.assertRaises(Denied):
                self.check(raw=raw)

    def test_original_observation_and_publisher_frozen(self):
        with patch.object(v5, "OBSERVED_BLOB", "f" * 40):
            with self.assertRaises(Denied):
                self.check()
        with patch.object(v5, "PUBLISH_BLOB", "f" * 40):
            with self.assertRaises(Denied):
                self.check()


if __name__ == "__main__":
    unittest.main()
