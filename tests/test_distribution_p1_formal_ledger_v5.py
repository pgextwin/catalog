#!/usr/bin/env python3
"""Issue #112 hostile v5 formal record integrity; NEVER mocks Sigstore as PASS."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from distribution_manifest_v1 import Denied
import distribution_p1_formal_ledger_v5 as v5


class RealCrossAttemptFormalV5(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc=json.loads(v5.V5.read_text("utf-8"))
        cls.v4=v5.V4.read_bytes()
        cls.v3=v5.V3.read_bytes()
        cls.pins=v5.PINS.read_bytes()
        cls.fleet=v5.FLEET.read_bytes()

    def check(self,doc=None,previous=None):
        raw=json.dumps(self.doc if doc is None else doc,ensure_ascii=False).encode("utf-8")
        # For negative document mutations, bypass exact-Blob preflight to
        # assert both blob trust and semantic gates separately via script.
        return v5.validate(raw,self.v4 if previous is None else previous,
                           self.v3,self.pins,self.fleet)

    def test_original_sealed_four_genuine_proof_rows_and_65_nonpublishing(self):
        result=v5.validate(v5.V5.read_bytes(),self.v4,self.v3,self.pins,self.fleet)
        self.assertEqual(result["formalP1Accepted"],65)
        self.assertEqual(result["newRows"],4)
        self.assertEqual(result["remainingDenied"],5)
        self.assertEqual(result["historicalSourceAccepted"],0)
        self.assertFalse(result["publicationAuthorized"])

    def test_identity_tamper_and_prior_source_ledger_replay_denied(self):
        mutations=[
          ("pgMajor",18),("releaseId",1),("assetId",628346168),
          ("assetName","orafce-fake.zip"),("buildJobId",114248008555),
          ("runId",38128142145),("buildAttempt",2),
          ("finalPublicationAttempt",1),("publishJobId",0),
          ("originalBuildAttempt1RunConclusion","success"),
          ("originalBuildJobConclusion","failure"),
          ("finalPublicationAttempt2RunConclusion","failure"),
          ("originalPublicationJobConclusion","skipped"),
          ("zipSha256","a"*64),("artifactArchiveSha256","b"*64),
          ("bundleSha256","c"*64),("rowReceiptSha256","d"*64),
          ("packagingSha","e"*40),("signerSha","f"*40),
          ("verificationProfile","historical/windows.yml/push/v1"),
          ("signatureVerified",False),("integrityVerified",False),
          ("workIndividualAuditRequired",True)]
        for key,wrong in mutations:
            with self.subTest(key=key):
                doc=copy.deepcopy(self.doc)
                doc["newAcceptedRows"][0][key]=wrong
                with self.assertRaises(Denied):
                    self.check(doc)
        with self.assertRaises(Denied):
            self.check(previous=self.v4.replace(b'"formalP1Accepted": 61',
                                                   b'"formalP1Accepted": 62'))

    def test_duplicate_extra_new_row_and_unaccepted_false_counts_denied(self):
        for key,val in (
            ("newAcceptedCount",5),("formalP1Accepted",70),
            ("remainingDenied",0),("historicalSourceAccepted",4),
            ("historicalSourceAcceptedRows",[{"extension":"orafce","pgMajor":14}]),
            ("fleetComplete",True),("p1","PASS"),("p2","GO"),
            ("publicationAuthorized",True),("distributionAuthorized",True),
            ("formalDistribution","ALLOW"),
            ("originalOrafceAttempt1FailureNotReclassified",False),
            ("failedPlpgsqlCheckPromotionRunUnwaived",False),
        ):
            with self.subTest(key=key):
                doc=copy.deepcopy(self.doc)
                doc[key]=val
                with self.assertRaises(Denied):
                    self.check(doc)
        dup=copy.deepcopy(self.doc)
        dup["newAcceptedRows"].append(copy.deepcopy(dup["newAcceptedRows"][0]))
        with self.assertRaises(Denied):
            self.check(dup)

    def test_forged_diagnostic_artifact_and_trusted_root_denied(self):
        for key,wrong in (
            ("runId",38984927984),
            ("artifactId",12082613192),
            ("artifactSha256","0"*64),
            ("summarySha256","1"*64),
            ("orafceCommonReceiptSha256","2"*64),
            ("officialGhSha256","3"*64),
            ("trustedRootSha256","4"*64),
            ("fourGenuineDualSigstoreProofs",False),
            ("artifactIsDiagnosticOnly",False),
        ):
            with self.subTest(key=key):
                doc=copy.deepcopy(self.doc)
                doc["audit"][key]=wrong
                with self.assertRaises(Denied):
                    self.check(doc)

    def test_duplicate_json_fields_rejected(self):
        raw=v5.V5.read_bytes().replace(
            b'"formalP1Accepted": 65',
            b'"formalP1Accepted": 65, "formalP1Accepted": 70')
        with self.assertRaises(Denied):
            v5.validate(raw,self.v4,self.v3,self.pins,self.fleet)


if __name__=="__main__":
    unittest.main()
