#!/usr/bin/env python3
"""Issue #112 separate formal-source v2 hostile tests. Fixture != real crypto."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from distribution_manifest_v1 import Denied
from distribution_p1_historical_fleet import blob_sha
import distribution_p1_historical_source_ledger_v2 as v2

class HistoricalSourceFormalV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = v2.V2.read_bytes()
        cls.data, cls.identities = v2.validate_ledger(cls.raw)

    def mutate(self, f):
        candidate = copy.deepcopy(self.data)
        f(candidate)
        raw = (json.dumps(candidate, ensure_ascii=False, indent=2) + "\n").encode()
        with patch.object(v2, "V2_GIT_BLOB", blob_sha(raw)):
            with self.assertRaises(Denied):
                v2.validate_ledger(raw)

    def test_real_ledger_sealed_zero_previous_and_40_new(self):
        self.assertEqual(len(self.identities), 40)
        self.assertEqual(self.data["sourceFormalAccepted"], 40)
        self.assertEqual(self.data["previousSourceFormalAccepted"], 0)
        self.assertEqual(self.data["p1FormalAccepted"], 65)
        self.assertEqual(self.data["sourceAudit"]["originalP1Denials"], 5)
        self.assertFalse(self.data["publicationAuthorized"])
        self.assertFalse(self.data["distributionAuthorized"])

    def test_altered_ledger_raw_even_whitespace_rejected(self):
        with self.assertRaises(Denied):
            v2.validate_ledger(self.raw + b"\n")

    def test_previous_ledger_change_rejected(self):
        self.mutate(lambda d: d.update(previousLedgerGitBlob="f"*40))
        self.mutate(lambda d: d.update(previousSourceFormalAccepted=40))

    def test_changed_source_hash_or_duplicate_receipt_rejected(self):
        self.mutate(lambda d: d["acceptedRows"][0].update(sourceReceiptSha256="abc"))
        self.mutate(lambda d: d["acceptedRows"][1].update(
            sourceReceiptSha256=d["acceptedRows"][0]["sourceReceiptSha256"]))

    def test_wrong_asset_pg_source_job_run_attempt_rejected(self):
        for field, value in [("assetId",42), ("pgMajor",19),
                             ("originalZipSha256","0"*64),
                             ("originalRunId",42), ("originalRunAttempt",9),
                             ("originalBuildJobId",42), ("originalPublishJobId",42),
                             ("repositoryId",42), ("releaseId",42)]:
            with self.subTest(field=field):
                self.mutate(lambda d,f=field,v=value: d["acceptedRows"][0].update({f:v}))

    def test_cross_row_swap_duplicate_missing_rejected(self):
        self.mutate(lambda d: d["acceptedRows"].pop())
        self.mutate(lambda d: d["acceptedRows"].append(copy.deepcopy(d["acceptedRows"][0])))
        self.mutate(lambda d: d["acceptedRows"][0].update(extension="orafce"))
        self.mutate(lambda d: d["acceptedRows"][0].update(
            sourceReceiptSha256=d["acceptedRows"][1]["sourceReceiptSha256"]))

    def test_false_run_and_artifact_identity_rejected(self):
        for k, v in [("runId",1),("runCommit","0"*40),("artifactId",1),
                     ("artifactZipSha256","f"*64),("artifactRunConclusion","success"),
                     ("originalP1Denials",0),("sourceCandidateCount",0)]:
            with self.subTest(key=k):
                self.mutate(lambda d,k=k,v=v: d["sourceAudit"].update({k:v}))

    def test_forged_counts_and_publication_rejected(self):
        for k,v in [("sourceFormalAccepted",41),("p1FormalAccepted",70),
                    ("p1","GO"),("p2","GO"),("publicationAuthorized",True),
                    ("distributionAuthorized",True),("formalDistribution","ALLOW")]:
            with self.subTest(key=k):
                self.mutate(lambda d,k=k,v=v:d.update({k:v}))

    def test_unrelated_metadata_and_signature_profile_not_enough(self):
        self.mutate(lambda d:d["acceptedRows"][0].update(signatureVerified=True))
        self.mutate(lambda d:d["acceptedRows"][0].update(upstreamCommit="a"*40))

    def test_wrong_original_archive_rejected_before_any_acceptance(self):
        with self.assertRaises(Denied):
            v2.validate_artifact(b"fake\x00not-cryptographic-evidence")
        with self.assertRaises(Denied):
            v2.validate_artifact(b"PK\x03\x04fixture-but-no-original-SHA")
        # A spoofed matching JSON does not make an audit ZIP trusted.

if __name__=="__main__":
    unittest.main()
