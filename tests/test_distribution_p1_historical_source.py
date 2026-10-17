#!/usr/bin/env python3
"""Hostile offline tests. Fixtures are NEVER original-byte/Sigstore evidence."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from distribution_manifest_v1 import Denied
from distribution_p1_historical_fleet import pins_load, LOG_BLOBS
from distribution_p1_historical_source import (
    INVENTORY, LEDGER, TARGETS, MAJORS, load_inventory,
    source_receipt, source_summary, validate_formal_v1)
from distribution_p1_formal_ledger_v5 import V5

class SourceOriginalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fleet = json.loads((ROOT / "config/issue112-p1-fleet-pins-20261017.json").read_text())
        raw = (ROOT / "config/issue112-p1-historical-source-pins-20261017.json").read_bytes()
        cls.pins = pins_load(raw, cls.fleet)
        cls.original = INVENTORY.read_bytes()
        cls.identity = load_inventory(cls.original, cls.pins, cls.fleet)
    def row(self):
        return copy.deepcopy(self.identity[("pg_cron", 15)])
    def release(self, identity):
        return {"type":"release","extension": identity["extension"],
                "repositoryId":identity["repositoryId"],"releaseId":identity["releaseId"],
                "allAssetsRehashed":True,"allPgZipCrcVerified":True,
                "allPgSpdxGrypeStructured":True,
                "assetIds":{identity["assetName"]:identity["assetId"]},
                "assetSha256":{identity["assetName"]:identity["originalZipSha256"]}}
    def p1(self, identity):
        return {"type":"row","extension": identity["extension"],"pgMajor":identity["pgMajor"],
                "repositoryId":identity["repositoryId"],"releaseId":identity["releaseId"],
                "assetId": identity["assetId"],"packagingSha":identity["packagingSha"],
                "decision":"PASS_CANDIDATE","verificationOrigin":"genuine",
                "verificationProfile":"historical/windows.yml/push/v1",
                "signatureVerified":True,"integrityVerified":True,
                "runId":identity["originalRunId"],"runAttempt":identity["originalRunAttempt"],
                "officialGhSha256":self.fleet["officialGhSha256"][0],
                "trustedRootSha256":self.fleet["rootSha256"],
                "signatureProof":{
                    "buildJobId":identity["originalBuildJobId"],
                    "publicationJobId":identity["originalPublishJobId"],
                    "originalCheckoutJobId":identity["originalBuildJobId"],
                    "originalCheckoutRunAttempt":identity["originalRunAttempt"],
                    "originalCheckoutArchiveBlob":LOG_BLOBS[identity["extension"]],
                    "workflowBlob":identity["workflowGitBlob"],
                    "configBlob":identity["configGitBlob"],"signerSha":identity["signerSha"],
                    "upstreamRepository":identity["upstreamRepository"],
                    "upstreamRef":identity["upstreamRef"],
                    "upstreamCommit":"b"*40,
                    "originalCheckoutLogSha256":"c"*64,
                    "bundleSha256":"d"*64}}
    def observe(self, identity, release=None, p1=None):
        return source_receipt(identity, release if release is not None else self.release(identity),
                              p1 if p1 is not None else self.p1(identity),
                              official_gh_sha=self.fleet["officialGhSha256"][0],
                              trusted_root_sha=self.fleet["rootSha256"])
    def test_complete_fixed_metadata_40(self):
        self.assertEqual(len(self.identity), 40)
        self.assertEqual(set(self.identity), {(name,pg) for name in TARGETS for pg in MAJORS})
        self.assertEqual(self.identity[("pg_bigm",14)]["assetId"],626562095)
    def test_zero_formal_source_ledger_chain(self):
        self.assertEqual(validate_formal_v1(LEDGER.read_bytes())["sourceFormalAccepted"],0)
        self.assertEqual(json.loads(V5.read_bytes())["formalP1Accepted"],65)
    def test_byte_sealed_source_ledger_rejects_whitespace_replay(self):
        with self.assertRaises(Denied):
            validate_formal_v1(LEDGER.read_bytes() + b"\\n")
    def test_fake_formal_acceptance_rejected(self):
        data=json.loads(LEDGER.read_bytes())
        for change in [
            {"sourceFormalAccepted":40},
            {"acceptedRows":[{"extension":"pg_cron","pgMajor":15}]},
            {"p1FormalAccepted":70},
            {"publicationAuthorized":True},
            {"previousP1LedgerGitBlob":"f"*40},
            {"formalDistribution":"ALLOW"},
        ]:
            bad={**data,**change}
            with self.subTest(change=change), self.assertRaises(Denied):
                validate_formal_v1(json.dumps(bad).encode())
    def test_metadata_misuse_rejected(self):
        for key,value in [("assetId",7),("pgMajor",19),("originalRunAttempt",2),
                          ("configGitBlob","a"*40),("originalZipSha256","0"*64),
                          ("extension","orafce"),("originalBuildJobId",0)]:
            bad=json.loads(self.original)
            row=next(x for x in bad["rows"] if x["extension"]=="pg_cron" and x["pgMajor"]==15)
            row[key]=value
            with self.subTest(key=key), self.assertRaises(Denied):
                load_inventory(json.dumps(bad).encode(),self.pins,self.fleet)
    def test_duplicate_and_missing_metadata_rejected(self):
        for op in ("remove","duplicate","swap"):
            bad=json.loads(self.original)
            if op=="remove":bad["rows"].pop()
            elif op=="duplicate":bad["rows"].append(bad["rows"][-1])
            else:bad["rows"][0]["assetId"]=bad["rows"][1]["assetId"]
            with self.subTest(op=op),self.assertRaises(Denied):
                load_inventory(json.dumps(bad).encode(),self.pins,self.fleet)
    def test_unsigned_and_failure_cannot_be_source_candidate(self):
        ident=self.row()
        for key,value in [("decision","DENY"),("signatureVerified",False),
                          ("integrityVerified",False),("runAttempt",2),
                          ("verificationProfile","main/promote.yml"),
                          ("assetId",15),("officialGhSha256","e"*64)]:
            fake=self.p1(ident);fake[key]=value
            with self.subTest(key=key):
                self.assertEqual(self.observe(ident,p1=fake)["decision"],"BLOCKED")
    def test_forged_checkout_source_and_run_id_rejected(self):
        ident=self.row()
        for key,value in [("upstreamCommit","bad"),("upstreamRepository","other/other"),
                          ("originalCheckoutJobId",888),("publicationJobId",555),
                          ("originalCheckoutRunAttempt",2),("configBlob","f"*40),
                          ("bundleSha256","bad"),("originalCheckoutLogSha256","bad")]:
            fake=self.p1(ident);fake["signatureProof"][key]=value
            with self.subTest(key=key):
                self.assertEqual(self.observe(ident,p1=fake)["decision"],"BLOCKED")
    def test_cross_release_and_changed_sha_rejected(self):
        ident=self.row()
        for key,value in [("assetIds",{ident["assetName"]:42}),
                          ("assetSha256",{ident["assetName"]:"e"*64}),
                          ("releaseId",1),("allAssetsRehashed",False)]:
            fake=self.release(ident);fake[key]=value
            with self.subTest(key=key):
                self.assertEqual(self.observe(ident,release=fake)["decision"],"BLOCKED")
    def test_pg14_one_off_exception_not_replayed(self):
        ident=self.identity[("pg_bigm",14)]
        self.assertEqual(self.observe(ident)["decision"],"BLOCKED")
        signed=self.p1(ident)
        signed["signatureProof"]["sourceOnlySeparatePG14Rerun"]=True
        self.assertEqual(self.observe(ident,p1=signed)["decision"],"SOURCE_PASS_CANDIDATE")
        self.assertIs(self.observe(ident,p1=signed)["formalSourceAccepted"],False)
    def test_candidate_observation_never_formal_admission(self):
        # A forged in-memory fixture may only prove parser wiring, never real crypto.
        receipt=self.observe(self.row())
        self.assertEqual(receipt["decision"],"SOURCE_PASS_CANDIDATE",receipt["reason"])
        self.assertIs(receipt["formalSourceAccepted"],False)
        self.assertIs(receipt["publicationAuthorized"],False)
        rows=[{"extension":name,"pgMajor":pg,"decision":"BLOCKED",
               "formalSourceAccepted":False,"publicationAuthorized":False,
               "distributionAuthorized":False} for name in TARGETS for pg in MAJORS]
        rows[0] = receipt | {"extension":"pg_bigm","pgMajor":14}
        summary=source_summary(rows)
        self.assertEqual(summary["sourceFormalAccepted"],0)
        self.assertEqual(summary["sourceCandidatesNotYetFormallyAdmitted"],1)
    def test_missing_duplicate_receipts_rejected(self):
        rows=[{"extension":name,"pgMajor":pg,"decision":"BLOCKED",
               "formalSourceAccepted":False,"publicationAuthorized":False,
               "distributionAuthorized":False} for name in TARGETS for pg in MAJORS]
        for modified in [rows[:-1], rows[:-1]+[rows[0]], [dict(rows[0],formalSourceAccepted=True)]+rows[1:]]:
            with self.assertRaises(Denied):
                source_summary(modified)

if __name__=="__main__":
    unittest.main()
