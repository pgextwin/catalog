"""Bounded offline tests of unsigned portalcorp intake and signed exact-source gate."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from external_direct_get_intake import validate_intake
from validate_public_get_pin import validate_document, ROW_KEYS, Denied

NOW = datetime(2026, 11, 9, tzinfo=timezone.utc)
INTAKE = ROOT / "config/issue112-portalcorp-pg16-original-get-intake-v1.json"

def signed_example():
    source = json.loads(INTAKE.read_text(encoding="utf-8"))
    row = {key: source["records"][0][key] for key in ROW_KEYS
           if key in source["records"][0]}
    row.update(approvedOperation="ORIGINAL_PROVIDER_GET_ONLY",
               downloadAuthorized=True, mirrorAuthorized=False)
    return dict(
        schemaVersion="pgextwin-external-direct-get-admission/v1",
        sourceKind="EXTERNAL_GITHUB_RELEASE_ASSET",
        issuerRepository="pgextwin/build", issuerCommit="a"*40,
        catalogCommit="b"*40, issuerEvent="workflow_dispatch",
        issuerRunId=54321, issuerRunAttempt=1,
        ownerActor="ShutenOishi", ownerId=27071164,
        publisherEnvironment="external-direct-provider-publisher",
        publisherAppId=5609317, approvedOperation="ORIGINAL_PROVIDER_GET_ONLY",
        issuedAt="2026-11-09T00:00:00Z", expiresAt="2026-11-09T06:00:00Z",
        downloadAuthorized=True, mirrorAuthorized=False,
        redistributionAuthorized=False, records=[row])

class PortalcorpSignedSourceTests(unittest.TestCase):
    def test_unsigned_intake_still_denies(self):
        doc=json.loads(INTAKE.read_text(encoding="utf-8"))
        self.assertEqual(len(validate_intake(doc)), 1)
        self.assertFalse(doc["downloadAuthorized"])
        self.assertFalse(doc["redistributionAuthorized"])
        with self.assertRaises(Denied):
            validate_document(doc, "run-54321", now=NOW, source="portalcorp_pgvector")

    def test_exact_source_only_and_expiry(self):
        doc=signed_example()
        self.assertEqual(validate_document(doc, "run-54321", now=NOW,
                                           source="portalcorp_pgvector"), "ACTIVE")
        self.assertEqual(validate_document(doc, "run-54321",
                                           now=NOW+timedelta(hours=7),
                                           source="portalcorp_pgvector"),
                         "EXPIRED_ARCHIVE_DOWNLOAD_DENY")
        for key, val in (
            ("assetId",1), ("originalSha256","0"*64),
            ("sourceRepo","andreiramani/pgvector_pgsql_windows"),
            ("pgMajor","18"), ("mirrorAuthorized",True),
            ("licenseUrl","https://evil.invalid/LICENSE"),
            ("noticeTreatment","no review")):
            fake=copy.deepcopy(doc)
            fake["records"][0][key]=val
            with self.subTest(key=key), self.assertRaises(Denied):
                validate_document(fake, "run-54321", now=NOW,
                                  source="portalcorp_pgvector")
        with self.assertRaises(Denied):
            validate_document(doc, "run-54321", now=NOW, source="hypopg")
if __name__=="__main__":
    unittest.main()
