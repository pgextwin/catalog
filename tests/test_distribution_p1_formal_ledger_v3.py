#!/usr/bin/env python3
"""Hostile noncryptographic exact-v3 receipt pin reconciliation."""
import copy
import json
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from distribution_manifest_v1 import Denied
import distribution_p1_formal_ledger_v3 as v3


class ExactFormalV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prior = v3.PRIOR_LEDGER.read_bytes()
        cls.ledger = json.loads(v3.LEDGER.read_text(encoding="utf-8"))

    def check(self, document, prior=None):
        return v3.validate(
            json.dumps(document, ensure_ascii=False).encode("utf-8"),
            self.prior if prior is None else prior)

    def test_exact_original_five_genuine_sigstore_rows(self):
        result = self.check(self.ledger)
        self.assertEqual(result["formallyAccepted"], 6)
        self.assertEqual(result["historicalSourceAccepted"], 0)
        self.assertIs(result["publicationAuthorized"], False)
        self.assertEqual(len(v3.expected_rows()), 5)
        self.assertEqual([r["pgMajor"] for r in v3.expected_rows()],
                         [14, 15, 16, 17, 18])
        self.assertTrue(all(row["observation"].startswith("Work個別監査不要")
                            for row in v3.expected_rows()))

    def test_unchanged_prior_ledger_byte_pin(self):
        with self.assertRaises(Denied):
            self.check(self.ledger, self.prior + b"\n")
        with self.assertRaises(Denied):
            self.check(self.ledger, b"{}")

    def test_missing_duplicate_wrong_asset_and_identity_denied(self):
        variations = []
        a = copy.deepcopy(self.ledger)
        a["acceptedRows"] += [a["acceptedRows"][-1]]
        variations.append(a)
        a = copy.deepcopy(self.ledger)
        a["acceptedRows"].pop()
        variations.append(a)
        for key, replacement in (
            ("assetId", 999), ("releaseId", 999),
            ("repositoryId", 999), ("zipSha256", "0" * 64),
            ("signerSha", "0" * 40), ("runId", 1),
            ("runAttempt", 2), ("profile", "historical-pg_bigm-pg14/1"),
            ("rowReceiptSha256", "f" * 64),
            ("slsaAndSpdxBundleSha256", "f" * 64),
            ("trustedRootSha256", "f" * 64), ("signatureVerified", False),
            ("integrityVerified", False), ("publicationJobId", 999),
        ):
            a = copy.deepcopy(self.ledger)
            a["acceptedRows"][1][key] = replacement
            variations.append(a)
        for a in variations:
            with self.subTest(altered=a.get("acceptedRows", [])[:2]), self.assertRaises(Denied):
                self.check(a)

    def test_untrusted_run_or_artifact_and_fake_success_denied(self):
        for key, bad in (
            ("runId", 11), ("runAttempt", 2),
            ("runConclusion", "success"), ("headSha", "0" * 40),
            ("originalReleaseReceiptSha256", "0" * 64),
            ("summaryReceiptSha256", "0" * 64),
            ("diagnosticZipSha256", "0" * 64),
            ("artifactId", 1), ("officialGhBinarySha256", "0" * 64),
            ("publisherOriginalRunId", 38128142145),
            ("publisherConclusion", "failure"),
        ):
            a = copy.deepcopy(self.ledger)
            a["genuineRunner"][key] = bad
            with self.subTest(key=key), self.assertRaises(Denied):
                self.check(a)

    def test_status_source_and_unverified_extra_row_denied(self):
        for key, bad in (
            ("formalP1Accepted", 5), ("formalP1Accepted", 7),
            ("historicalSourceAccepted", 1), ("historicalSourceAcceptedRows", [{}]),
            ("fleetComplete", True), ("publicationAuthorized", True),
            ("distributionAuthorized", True), ("p1", "PASS"), ("p2", "GO"),
        ):
            a = copy.deepcopy(self.ledger)
            a[key] = bad
            with self.subTest(key=key), self.assertRaises(Denied):
                self.check(a)
        with self.assertRaises(Denied):
            self.check(dict(self.ledger, newSyntheticClaim=True))

    def test_duplicate_json_key_denied(self):
        body = v3.LEDGER.read_bytes()
        bad = body.replace(b'"formalP1Accepted": 6',
                           b'"formalP1Accepted": 6, "formalP1Accepted": 7', 1)
        self.assertNotEqual(body, bad)
        with self.assertRaises(Denied):
            v3.validate(bad, self.prior)


if __name__ == "__main__":
    unittest.main()
