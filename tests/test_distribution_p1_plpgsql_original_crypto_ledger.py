#!/usr/bin/env python3
"""Hostile static sealed crypto observation regression, never fake real Sigstore."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from distribution_manifest_v1 import Denied,strict_json
import distribution_p1_plpgsql_original_crypto_ledger as ledger


class OriginalFiveCryptoWitness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.witness=strict_json(ledger.WITNESS.read_bytes())

    def test_actual_sealed_original_observation_metadata(self):
        self.assertEqual(ledger.witness_validate(self.witness)["formalP1Accepted"],65)
        self.assertEqual(len(self.witness["pgRows"]),5)
        self.assertFalse(self.witness["manualApprovalToPublishedEventCausalityVerified"])

    def test_reject_forged_acceptance_and_missing_causality(self):
        attacks=[
            ("run-success","originalRunConclusion","success"),
            ("publish-success","originalPublishJobConclusion","success"),
            ("wrong-run","sourceReadOnlyRunId",1),
            ("wrong-head","sourceProtectedMainSha","0"*40),
            ("wrong-artifact","sourceDiagnosticArtifactId",1),
            ("wrong-archive-hash","sourceDiagnosticArtifactArchiveSha256","0"*64),
            ("wrong-inner-hash","sourceDiagnosticEntrySha256","0"*64),
            ("wrong-event-hash","pinnedCanonicalEventSha256","0"*64),
            ("wrong-tuf-root","trustedRootSha256","0"*64),
            ("swapped-release","releaseId",1),
            ("replay-tag","releaseTag","arbitrary"),
            ("fake-token","eventPublishingToken","GITHUB_TOKEN"),
            ("claimed-http","eventPublishingHttpMethod","PATCH"),
            ("claimed-causality","manualApprovalToPublishedEventCausalityVerified",True),
            ("recount","formalP1Accepted",70),
            ("unauthorized-distribution","distributionAuthorized",True),
            ("misleading-P1","p1","PASS"),
        ]
        for name,key,value in attacks:
            altered=copy.deepcopy(self.witness)
            altered[key]=value
            with self.subTest(name=name),self.assertRaises(Denied):
                ledger.witness_validate(altered)

    def test_reject_pg_row_substitution_duplicate_or_signature_replay(self):
        for name,modify in [
            ("duplicate",lambda w:w["pgRows"].append(copy.deepcopy(w["pgRows"][0]))),
            ("major-substitution",lambda w:w["pgRows"][0].update(pgMajor=18)),
            ("original-job-substitution",lambda w:w["pgRows"][0].update(originalBuildJobId=2)),
            ("bundle-forgery",lambda w:w["pgRows"][4].update(signedBundleSha256="f"*64)),
            ("published-zip-hash",lambda w:w["pgRows"][2].update(publicZipSha256="f"*64)),
            ("spdx-hash",lambda w:w["pgRows"][2].update(publicSpdxSha256="f"*64)),
            ("grype-hash",lambda w:w["pgRows"][2].update(publicGrypeSha256="f"*64)),
            ("row-missing",lambda w:w["pgRows"].pop()),
        ]:
            w=copy.deepcopy(self.witness)
            modify(w)
            with self.subTest(name=name),self.assertRaises(Denied):
                ledger.witness_validate(w)

    def test_unpinned_archive_must_never_count_as_crypto(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"fake.zip"
            p.write_bytes(b"not a real Actions Artifact")
            with self.assertRaises(Denied):
                ledger.validate_archived_diagnostic(p)

    def test_capture_injection_not_accepted(self):
        with patch.object(ledger,"verify_protected_capture",side_effect=Denied("changed Event")):
            with self.assertRaises(Denied):
                ledger.witness_validate(self.witness)


if __name__=="__main__":
    unittest.main()
