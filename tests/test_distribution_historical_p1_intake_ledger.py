"""Issue #112: hostile evidence intake tests are NOT cryptographic proofs."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import distribution_historical_p1_intake_ledger as intake


class HistoricalIntakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = intake.LEDGER.read_bytes()
        cls.receipt = intake.RECEIPT.read_bytes()

    def denied(self, ledger=None, receipt=None, archive=None):
        with self.assertRaises(intake.Denied):
            intake.reconcile(ledger if ledger is not None else self.ledger,
                             receipt if receipt is not None else self.receipt, archive)

    def mutate(self, transform):
        obj = json.loads(self.ledger)
        transform(obj)
        return json.dumps(obj).encode()

    def test_pinned_real_receipt_reference_not_formal_p1(self):
        result = intake.reconcile(self.ledger, self.receipt)
        self.assertEqual(result["formalP1RowsAccepted"], 0)
        self.assertEqual(result["historicalSourceAccepted"], 0)
        self.assertEqual(result["formalP1RowsExpected"], 70)
        self.assertEqual(result["releaseAssetBytesIndependentlyRehashedByWork"], 4)
        self.assertTrue(result["receiptSha256Matched"])
        self.assertFalse(result["archiveSha256Matched"])
        self.assertFalse(result["publicationAuthorized"])
        self.assertEqual(result["p1"], "BLOCKED")

    def test_tampered_receipt_denied(self):
        self.denied(receipt=self.receipt.replace(b'"signatureVerified": true',
                                                 b'"signatureVerified": false'))
        self.denied(receipt=self.receipt + b" ")
        self.denied(receipt=b'{"signatureVerified":true}')

    def test_unknown_or_duplicate_key_denied(self):
        self.denied(ledger=self.ledger[:-2] + b', "formalP1RowsAccepted":1}\n')
        self.denied(ledger=b'{"schema":1,"schema":2}')
        self.denied(receipt=b'{"rowEvidenceComplete":true,"rowEvidenceComplete":false}')

    def test_no_implicit_16_asset_or_acceptance_promotion(self):
        for key, value in [
            ("rehashAssets", 16),
            ("releaseAllAssetsRehashed", True),
            ("formalP1RowAccepted", True),
            ("historicalSourceFormallyAccepted", True),
            ("publicationAuthorized", True),
            ("distributionAuthorized", True),
            ("fleetComplete", True),
            ("workReportedTechnicalPass", 1),
        ]:
            self.denied(ledger=self.mutate(
                lambda obj: obj["states"].__setitem__(key, value)))

    def test_substituted_row_or_identity_denied(self):
        for key, value in [
            ("extension", "plpgsql_check"),
            ("pgMajor", 15),
            ("catalogSnapshot", "f" * 40),
            ("releaseId", 408449467),
            ("zipAssetId", 626562096),
            ("runAttempt", 2),
            ("historicalEvent", "workflow_dispatch"),
            ("upstreamSha", "a" * 40),
        ]:
            self.denied(ledger=self.mutate(
                lambda obj: obj["row"].__setitem__(key, value)))

    def test_archive_only_checked_as_whole_bytes(self):
        self.denied(archive=b"not-original-archive")
        with self.assertRaises(intake.Denied):
            intake.reconcile(self.ledger, self.receipt, b"0" * intake.ARCHIVE_SIZE)

    def test_unknown_evidence_source_is_not_a_trust_anchor(self):
        for key, value in [
            ("receiptSha256", "f" * 64),
            ("archiveSha256", "f" * 64),
            ("verifierCommit", "0" * 40),
        ]:
            self.denied(ledger=self.mutate(
                lambda obj: obj["evidence"].__setitem__(key, value)))

    def test_missing_local_and_symlink_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "linked.json"
            p.symlink_to(intake.RECEIPT)
            with self.assertRaises(intake.Denied):
                intake.read_local(p, 16384)
            with self.assertRaises(intake.Denied):
                intake.read_local(Path(d) / "absent", 16384)

    def test_cli_is_read_only_and_fail_closed(self):
        self.assertEqual(intake.main([]), 0)
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_bytes(b"{}")
            self.assertEqual(intake.main(["--receipt", str(bad)]), 2)


if __name__ == "__main__":
    unittest.main()
