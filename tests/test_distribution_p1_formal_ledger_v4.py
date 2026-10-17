#!/usr/bin/env python3
"""Issue #112 hostile v4 acceptance RECORD-only tests.

These deliberately do not mock actual gh/TUF as genuine Sigstore PASS. The
actual protected-main Run 38984927984 is linked by immutable receipt SHA.
"""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from distribution_manifest_v1 import Denied
import distribution_p1_formal_ledger_v4 as v4


class Exact55HistoricalFormalIntake(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = v4.V4.read_bytes()
        cls.previous = v4.V3.read_bytes()
        cls.pins = v4.PINS.read_bytes()
        cls.fleet = v4.FLEET.read_bytes()
        cls.document = json.loads(cls.raw)

    def check(self, modified=None, **kwargs):
        raw = (json.dumps(modified).encode("utf-8")
               if modified is not None else self.raw)
        return v4.validate(raw, kwargs.get("previous", self.previous),
                           kwargs.get("pins", self.pins),
                           kwargs.get("fleet", self.fleet))

    def assert_denies(self, modified):
        with self.assertRaises(Denied):
            self.check(modified)

    def test_actual_55_receipts_and_61_total_formal_record(self):
        out = self.check()
        self.assertEqual(out["accepted"], 61)
        self.assertEqual(out["addedGenuineRows"], 55)
        self.assertEqual(out["remainingDenied"], 9)
        self.assertFalse(out["publicationAuthorized"])
        self.assertFalse(out["distributionAuthorized"])
        self.assertEqual(out["historicalSourceAccepted"], 0)
        self.assertEqual(out["decision"],
                         "V4_FORMAL_RECORD_INTEGRITY_VALID_NOT_A_CRYPTO_TEST")

    def test_immutable_v3_historical_registry_and_formal_v4(self):
        with self.assertRaises(Denied):
            self.check(previous=self.previous.replace(b'"formalP1Accepted": 6',
                                                      b'"formalP1Accepted": 7'))
        with self.assertRaises(Denied):
            self.check(pins=self.pins.replace(b'"runAttempt": 2',
                                             b'"runAttempt": 1'))
        invalid = json.dumps(self.document).encode("utf-8")
        with self.assertRaises(Denied):
            v4.validate(invalid, self.previous, self.pins, self.fleet)

    def test_false_denied_acceptance_and_publication_never_allowed(self):
        for key, value in (
            ("newAcceptedCount", 59), ("formalP1Accepted", 70),
            ("previousFormalAccepted", 0),
            ("historicalSourceAccepted", 40),
            ("historicalSourceAcceptedRows", [{"name": "orafce", "pg": 14}]),
            ("remainingDenied", 0), ("p1", "PASS"), ("p2", "GO"),
            ("fleetComplete", True),
            ("publicationAuthorized", True),
            ("distributionAuthorized", True),
            ("formalDistribution", "ALLOW"),
            ("plpgsqlCheckFailedOriginalRunUnwaived", False),
            ("orafceMixedAttemptPG14to17Denied", False),
        ):
            modified = copy.deepcopy(self.document)
            modified[key] = value
            with self.subTest(key=key):
                self.assert_denies(modified)

    def test_replay_duplicate_source_profile_or_wrong_attempt(self):
        for field, value in (
            ("extension", "plpgsql_check"), ("pgMajor", 19),
            ("assetId", 1),
            ("repositoryId", 1), ("releaseId", 1),
            ("assetName", "fake-pg14-windows-x64.zip"),
            ("runId", 38128142145), ("runAttempt", 2),
            ("signerSha", "f"*40), ("packagingSha", "f"*40),
            ("buildJobId", 1), ("publicationJobId", 1),
            ("profile", "historical-pg_bigm-pg14/1"),
            ("workIndividualAuditRequired", True),
            ("rowReceiptSha256", "0"*64),
        ):
            modified = copy.deepcopy(self.document)
            modified["newAcceptedRows"][0][field] = value
            with self.subTest(field=field):
                self.assert_denies(modified)
        for replacement in [
            self.document["newAcceptedRows"][0],
            dict(self.document["newAcceptedRows"][0], extension="wal2json"),
            dict(self.document["newAcceptedRows"][0],
                 extension="orafce", pgMajor=14),
        ]:
            modified = copy.deepcopy(self.document)
            modified["newAcceptedRows"][-1] = replacement
            self.assert_denies(modified)

    def test_bypass_outer_git_blob_fails_frozen_row_receipt_proof(self):
        """Even maliciously changing ledger hash constant alone cannot alter evidence."""
        modified = copy.deepcopy(self.document)
        modified["newAcceptedRows"][0]["rowReceiptSha256"] = "1"*64
        forged = json.dumps(modified, ensure_ascii=False).encode("utf-8")
        with patch.object(v4, "V4_GIT_BLOB", v4.git_blob(forged)):
            with self.assertRaises(Denied) as err:
                self.check(modified)
        # pass same serialized bytes so the independent canonical pin is reached
        forged_compact = json.dumps(modified).encode("utf-8")
        with patch.object(v4, "V4_GIT_BLOB", v4.git_blob(forged_compact)):
            with self.assertRaisesRegex(Denied, "original per-PG receipt SHA256"):
                v4.validate(forged_compact, self.previous, self.pins, self.fleet)

    def test_duplicate_json_properties_denied(self):
        raw = self.raw
        marker = b'"formalP1Accepted": 61'
        self.assertIn(marker, raw)
        malformed = raw.replace(marker, b'"formalP1Accepted": 61, "formalP1Accepted": 70')
        with patch.object(v4, "V4_GIT_BLOB", v4.git_blob(malformed)):
            with self.assertRaises(Denied):
                v4.validate(malformed, self.previous, self.pins, self.fleet)


if __name__ == "__main__":
    unittest.main()
