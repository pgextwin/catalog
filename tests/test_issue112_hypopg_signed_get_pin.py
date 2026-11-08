"""Adversarial exact HypoPG three-asset signed source parser tests, OFFLINE only."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from validate_public_get_pin import validate_document, scan, Denied, ROW_KEYS

NOW = datetime(2026, 11, 8, 7, 0, 0, tzinfo=timezone.utc)


def signed_example():
    intake = json.loads((ROOT / "config/issue112-hypopg-original-get-intake-v1.json").read_text())
    records = []
    for row in intake["records"]:
        r={key:row[key] for key in ROW_KEYS if key in row}
        r.update(approvedOperation="ORIGINAL_PROVIDER_GET_ONLY",
                 downloadAuthorized=True,mirrorAuthorized=False)
        records.append(r)
    return {
        "schemaVersion":"pgextwin-external-direct-get-admission/v1",
        "sourceKind":"EXTERNAL_GITHUB_RELEASE_ASSET",
        "issuerRepository":"pgextwin/build",
        "issuerCommit":"a"*40,"catalogCommit":"b"*40,
        "issuerEvent":"workflow_dispatch","issuerRunId":5432,
        "issuerRunAttempt":1,"ownerActor":"ShutenOishi","ownerId":27071164,
        "publisherEnvironment":"external-direct-provider-publisher",
        "publisherAppId":5609317,"approvedOperation":"ORIGINAL_PROVIDER_GET_ONLY",
        "issuedAt":"2026-11-08T07:00:00Z","expiresAt":"2026-11-08T13:00:00Z",
        "downloadAuthorized":True,"mirrorAuthorized":False,
        "redistributionAuthorized":False,"records":records,
    }


class HypoPGSigned(unittest.TestCase):
    def test_three_exact_assets_not_generic_catalog_authority(self):
        d=signed_example()
        self.assertEqual(validate_document(d,"run-5432",now=NOW,source="hypopg"),"ACTIVE")
        self.assertEqual(validate_document(d,"run-5432",now=NOW+timedelta(hours=9),
                                           source="hypopg"),"EXPIRED_ARCHIVE_DOWNLOAD_DENY")
        with self.assertRaises(Denied):
            validate_document(d,"run-5432",now=NOW,source="pg_trickle")

    def test_no_source_identity_or_hash_substitution(self):
        for name, field, value in (
            ("sha","originalSha256","0"*64),
            ("source","sourceRepo","laurenz/oracle_fdw"),
            ("asset","assetId",1),
            ("major","pgMajor","17"),
            ("license","licenseUrl","https://other.invalid/NOTICE"),
            ("mirror","mirrorAuthorized",True),
            ("pg18forgery","targetEnvironment","PostgreSQL 18 Windows x64"),
        ):
            doc=copy.deepcopy(signed_example())
            doc["records"][1][field]=value
            with self.subTest(case=name), self.assertRaises(Denied):
                validate_document(doc,"run-5432",now=NOW,source="hypopg")

    def test_missing_or_extra_records_denied(self):
        for records in (
            signed_example()["records"][:2],
            signed_example()["records"]+[signed_example()["records"][0]],
            list(reversed(signed_example()["records"])),
        ):
            doc=signed_example()
            doc["records"]=records
            with self.assertRaises(Denied):
                validate_document(doc,"run-5432",now=NOW,source="hypopg")

    def test_no_implicit_permission_from_unsigned_candidate(self):
        source=json.loads((ROOT/"config/issue112-hypopg-original-get-intake-v1.json").read_text())
        self.assertFalse(source["downloadAuthorized"])
        with self.assertRaises(Denied):
            validate_document(source,"run-5432",now=NOW,source="hypopg")

    def test_no_zip_store_and_directory_allowlist(self):
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d)/"external/signed-direct-get"
            entry=parent/"hypopg/run-5432"
            entry.mkdir(parents=True)
            (entry/"external-get-admission.json").write_text(json.dumps(signed_example()))
            (entry/"attestation.json").write_bytes(b"x"*250)
            result=scan(d,now=NOW,online=False)
            self.assertEqual(result[0]["source"],"hypopg")
            self.assertEqual(result[0]["status"],"ACTIVE")
            (entry/"provider.zip").write_bytes(b"fake")
            with self.assertRaises(Denied):scan(d,now=NOW,online=False)
            (entry/"provider.zip").unlink()
            (parent/"oracle_fdw").mkdir()
            with self.assertRaises(Denied):scan(d,now=NOW,online=False)


if __name__=="__main__":
    unittest.main()
