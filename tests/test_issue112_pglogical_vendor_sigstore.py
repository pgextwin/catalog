"""Fail-closed, offline tests for Issue #112 vendor Sigstore receipt validation."""
from __future__ import annotations

import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
from issue112_pglogical_original_windows import PINS
from issue112_pglogical_vendor_sigstore import verified_statement, RUN_ID

PREDICATE = "https://slsa.dev/provenance/v1"


def valid_proof():
    subjects = [
        {"name": "pglogical-2.4.8-pg" + str(pg) + "-w1-x64.zip",
         "digest": {"sha256": pin[2]}}
        for pg, pin in sorted(PINS.items())
    ]
    return [{
        "verificationResult": {
            "statement": {
                "predicateType": PREDICATE,
                "subject": subjects,
                "predicate": {
                    "runDetails": {
                        "metadata": {
                            "invocationId": (
                                "https://github.com/semihkiroglu/pglogical-windows/"
                                "actions/runs/" + RUN_ID + "/attempts/1"
                            )
                        }
                    }
                }
            }
        }
    }]


class VendorSigstoreTests(unittest.TestCase):
    def test_exact_five_originals(self):
        for pg in PINS:
            name = "pglogical-2.4.8-pg" + str(pg) + "-w1-x64.zip"
            verified_statement(valid_proof(), name, PINS[pg][2])

    def test_single_expected_original(self):
        proof = valid_proof()
        proof[0]["verificationResult"]["statement"]["subject"] = [
            copy.deepcopy(proof[0]["verificationResult"]["statement"]["subject"][0])
        ]
        verified_statement(proof, "pglogical-2.4.8-pg14-w1-x64.zip", PINS[14][2])

    def test_reject_modified_hash(self):
        proof = valid_proof()
        proof[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            verified_statement(proof, "pglogical-2.4.8-pg14-w1-x64.zip", PINS[14][2])

    def test_reject_duplicate_subject(self):
        proof = valid_proof()
        items = proof[0]["verificationResult"]["statement"]["subject"]
        items[1] = copy.deepcopy(items[0])
        with self.assertRaises(ValueError):
            verified_statement(proof, "pglogical-2.4.8-pg14-w1-x64.zip", PINS[14][2])

    def test_reject_wrong_provider_run(self):
        proof = valid_proof()
        proof[0]["verificationResult"]["statement"]["predicate"]["runDetails"]["metadata"]["invocationId"] = (
            "https://github.com/semihkiroglu/pglogical-windows/actions/runs/1111111/attempts/1"
        )
        with self.assertRaises(ValueError):
            verified_statement(proof, "pglogical-2.4.8-pg14-w1-x64.zip", PINS[14][2])

    def test_reject_missing_requested_zip(self):
        with self.assertRaises(ValueError):
            verified_statement(valid_proof(), "pglogical-2.4.8-pg19-w1-x64.zip", "0" * 64)

    def test_reject_unsigned_predicate(self):
        proof = valid_proof()
        proof[0]["verificationResult"]["statement"]["predicateType"] = "https://spdx.dev/Document/v2.3"
        with self.assertRaises(ValueError):
            verified_statement(proof, "pglogical-2.4.8-pg14-w1-x64.zip", PINS[14][2])

    def test_reject_absent_verification(self):
        with self.assertRaises(ValueError):
            verified_statement([{"statement": {}}], "pglogical-2.4.8-pg14-w1-x64.zip", PINS[14][2])


if __name__ == "__main__":
    unittest.main()
