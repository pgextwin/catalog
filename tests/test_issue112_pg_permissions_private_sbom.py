"""Offline hostile tests for exact SQL-only, nonpublishing SPDX file inventory."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue112_sql_owned_archive import canonical_zip
from issue112_pg_permissions_source_pins import PINNED, NEW_COMMIT
from issue112_pg_permissions_owned_source_pilot import FLAGS, SCHEMA
from issue112_pg_permissions_private_sbom import spdx_inventory, NAMES


class PgPermissionsSpdxTests(unittest.TestCase):
    def setUp(self):
        self.pg = "18"
        self.members = {"LICENSE": b"synthetic upstream license test only\n"}
        for name in PINNED:
            if name != "LICENSE":
                self.members["share/extension/" + name] = ("synthetic: " + name).encode()
        self.receipt = {
            "schemaVersion": SCHEMA, "status": "CANDIDATE_ONLY",
            "kind": "PGEXTWIN_OWNED_SQL_SOURCE_NOT_CYBERTEC_ORIGINAL",
            "upstreamRepository": "cybertec-postgresql/pg_permissions",
            "upstreamCommit": NEW_COMMIT, "upstreamPackageVersion": "1.4.1",
            "sqlExtensionDefaultVersion": "1.4", "postgresqlMajor": "18",
            "fullUpstreamLicenseIncluded": True,
            "sourceFileSha256": {name: hashlib.sha256(self.members[
                "LICENSE" if name == "LICENSE" else "share/extension/" + name
            ]).hexdigest() for name in PINNED},
            **{flag: False for flag in FLAGS},
        }
        self.save_manifest()

    def save_manifest(self):
        self.members["SOURCE-INPUTS.json"] = (
            json.dumps(self.receipt, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()

    def document(self):
        return spdx_inventory(canonical_zip(self.members), self.members,
                              self.pg, "2026-11-13T01:02:03Z")

    def test_exact_ten_file_spdx_byte_ledger(self):
        result = self.document()
        self.assertEqual(set(self.members), NAMES)
        self.assertEqual(result["spdxVersion"], "SPDX-2.3")
        self.assertEqual(len(result["files"]), 10)
        self.assertEqual(len(result["relationships"]), 11)
        self.assertEqual(result["packages"][0]["versionInfo"], "1.4.1")
        self.assertEqual(result["creationInfo"]["created"], "2026-11-13T01:02:03Z")
        actual = {row["fileName"][2:]: row["checksums"][1]["checksumValue"]
                  for row in result["files"]}
        self.assertEqual(actual, {k: hashlib.sha256(v).hexdigest()
                                  for k, v in self.members.items()})
        self.assertEqual(result["packages"][0]["checksums"][0]["checksumValue"],
                         hashlib.sha256(canonical_zip(self.members)).hexdigest())
        self.assertNotIn("publicGetAuthorized", result)
        self.assertNotIn("distributionAuthorized", result)
        self.assertEqual(result["packages"][0]["licenseDeclared"], "NOASSERTION")

    def test_all_pg_majors_get_separate_canonical_receipts(self):
        hashes = set()
        for pg in ("14", "15", "16", "17", "18"):
            self.pg = pg
            self.receipt["postgresqlMajor"] = pg
            self.save_manifest()
            raw = canonical_zip(self.members)
            doc = self.document()
            hashes.add(hashlib.sha256(raw).hexdigest())
            self.assertIn("pg" + pg, doc["name"])
        self.assertEqual(len(hashes), 5)

    def test_permission_or_source_identity_escalation_denied(self):
        for field, value in [
            ("downloadAuthorized", True), ("publisherAuthorized", True),
            ("mirrorAuthorized", True), ("releaseAuthorized", True),
            ("independentSourceSignatureVerified", True),
            ("status", "PUBLIC_COMPLETE"), ("kind", "CYBERTEC_ORIGINAL"),
            ("upstreamCommit", "0" * 40), ("postgresqlMajor", "17"),
            ("fullUpstreamLicenseIncluded", False),
        ]:
            previous = self.receipt[field]
            self.receipt[field] = value
            self.save_manifest()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.document()
            self.receipt[field] = previous
            self.save_manifest()

    def test_wrong_member_hash_or_missing_member_denied(self):
        self.receipt["sourceFileSha256"]["LICENSE"] = "f" * 64
        self.save_manifest()
        with self.assertRaises(ValueError):
            self.document()
        self.receipt["sourceFileSha256"]["LICENSE"] = hashlib.sha256(
            self.members["LICENSE"]).hexdigest()
        self.save_manifest()
        self.members["evil.dll"] = b"MZ"
        with self.assertRaises(ValueError):
            self.document()
        del self.members["evil.dll"]
        del self.members["LICENSE"]
        with self.assertRaises(ValueError):
            self.document()

    def test_wrong_zip_bytes_pg_or_timestamp_denied(self):
        raw = canonical_zip(self.members)
        for wrong in (raw + b"trailing", raw[:-7]):
            with self.assertRaises(ValueError):
                spdx_inventory(wrong, self.members, "18")
        with self.assertRaises(ValueError):
            spdx_inventory(raw, self.members, "19")
        with self.assertRaises(ValueError):
            spdx_inventory(raw, self.members, "18", created="2026-11-13")

    def test_duplicate_receipt_json_keys_denied(self):
        self.members["SOURCE-INPUTS.json"] = (
            b'{"status":"CANDIDATE_ONLY","status":"PUBLIC_COMPLETE"}')
        with self.assertRaises(ValueError):
            self.document()


if __name__ == "__main__":
    unittest.main()
