#!/usr/bin/env python3
"""Hostile, offline checks for the exact one-row formal admission ledger."""
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from distribution_manifest_v1 import Denied
import distribution_p1_formal_ledger_v2 as v2


class LedgerContractTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(v2.LEDGER.read_text("utf-8"))

    def validate(self, obj):
        return v2.validate(json.dumps(obj).encode("utf-8"))

    def test_baseline_validates_and_never_authorizes_publication(self):
        result = self.validate(self.document)
        self.assertEqual(result["formalP1Accepted"], 1)
        self.assertEqual(result["historicalSourceAccepted"], 0)
        self.assertIs(result["publicationAuthorized"], False)
        self.assertEqual(result["decision"], "READONLY_BASELINE_VALID")

    def test_duplicate_or_undocumented_row_cannot_add_to_counter(self):
        for altered in (
            {"acceptedRows": self.document["acceptedRows"] * 2, "formalP1Accepted": 2},
            {"acceptedRows": self.document["acceptedRows"] * 2},
            {"formalP1Accepted": 2},
            {"formalP1Accepted": 0},
            {"historicalSourceAccepted": 1},
            {"historicalSourceAcceptedRows": [{"extension": "pg_bigm", "pgMajor": 14}]},
        ):
            with self.subTest(altered=altered), self.assertRaises(Denied):
                self.validate(dict(self.document, **altered))

    def test_untrusted_baseline_and_profile_replay_denied(self):
        for key, val in (
            ("repositoryId", 0), ("releaseId", 999), ("assetId", 626562100),
            ("pgMajor", 15), ("extension", "plpgsql_check"),
            ("profile", "main-promotion/v1"), ("verifierCommit", "a" * 40),
        ):
            a = copy.deepcopy(self.document)
            a["acceptedRows"][0][key] = val
            with self.subTest(key=key), self.assertRaises(Denied):
                self.validate(a)

    def test_publication_escalation_and_unknown_flags_denied(self):
        for key, value in (
            ("publicationAuthorized", True), ("distributionAuthorized", True),
            ("fleetComplete", True), ("p1", "PASS"), ("p2", "GO"),
        ):
            a = dict(self.document, **{key: value})
            with self.subTest(key=key), self.assertRaises(Denied):
                self.validate(a)
        with self.assertRaises(Denied):
            self.validate(dict(self.document, syntheticPass=True))

    def test_duplicate_json_key_fails_closed(self):
        data = v2.LEDGER.read_bytes().replace(b'"formalP1Accepted": 1',
                                                b'"formalP1Accepted": 1, "formalP1Accepted": 2')
        with self.assertRaises(Denied):
            v2.validate(data)


if __name__ == "__main__":
    unittest.main()
