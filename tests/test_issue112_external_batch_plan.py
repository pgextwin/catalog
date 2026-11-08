"""Synthetic and checked-in-source regressions for nonpublishing #112 batches."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue112_external_batch_plan import build, Denied, INPUTS, PROVIDERS


class Cohorts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "external").mkdir()
        provider = {"repo": "HypoPG/hypopg", "providerType": "upstream-official",
                    "extension": "hypopg", "assetPattern": "^hypopg.*\\.zip$"}
        self.providers = {"schemaVersion": "pgextwin-external-discovery-providers/v1",
                          "trust": "READ_ONLY_METADATA_NEVER_AUTHORIZE", "githubApiHost": "api.github.com",
                          "providers": [provider]}
        self.row = {"sourceRepo": "HypoPG/hypopg", "providerType": "upstream-official",
                    "extension": "hypopg", "pgMajor": "16", "upstreamVersion": "1.4.1",
                    "releaseTag": "1.4.1", "releaseId": 153113229, "assetId": 164673171,
                    "assetName": "hypopg-1.4.1-pg16-x64.zip", "apiDigest": None,
                    "originalSha256": None, "originalBytes": None,
                    "downloadAuthorized": False, "redistributionAuthorization": "not-authorized",
                    "historical": True}
        self.inputs = []
        for _ in INPUTS:
            self.inputs.append({"schemaVersion": "pgextwin-windows-source-candidates/v1",
                "trust": "UNVERIFIED_METADATA_ONLY", "publicationAuthorized": False,
                "redistributionAuthorized": False, "candidates": []})
        self.inputs[0]["candidates"] = [self.row]
        self.save()

    def save(self):
        (self.root / PROVIDERS).write_text(json.dumps(self.providers))
        for path, value in zip(INPUTS, self.inputs):
            (self.root / path).write_text(json.dumps(value))

    def test_cohort_deny_and_reusable(self):
        p = build(self.root)
        self.assertEqual((p["totalCandidateAssets"], p["reviewBatchCount"], p["admittedAssets"]), (1, 1, 0))
        self.assertFalse(p["downloadAuthorized"])
        self.assertFalse(p["batches"][0]["publisherInvocationAuthorized"])
        self.assertIn("INDEPENDENT_ORIGINAL_BYTES_NOT_PINNED", p["batches"][0]["records"][0]["blockers"])
        self.assertEqual(build(self.root), p)

    def test_bounded_independent_batches(self):
        for n in range(8):
            row = copy.deepcopy(self.row)
            row["assetId"] += n + 1
            row["assetName"] = f"hypopg-1.4.1-pg16-{n}.zip"
            self.inputs[0]["candidates"].append(row)
        self.save()
        p = build(self.root, max_batch=3)
        self.assertEqual([len(x["records"]) for x in p["batches"]], [3, 3, 3])
        self.assertTrue(all(not b["downloadAuthorized"] for b in p["batches"]))

    def test_held_provider_isolated(self):
        held = copy.deepcopy(self.row)
        held.update(sourceRepo="laurenz/oracle_fdw", providerType="upstream-official",
                    extension="oracle_fdw", assetId=91, assetName="oracle_fdw-2.9.0-pg18-win64.zip",
                    pgMajor="18")
        self.providers["providers"].append({"repo": "laurenz/oracle_fdw",
            "providerType": "upstream-official", "extension": "oracle_fdw",
            "assetPattern": "^oracle_fdw.*\\.zip$"})
        self.inputs[0]["candidates"].append(held)
        self.save()
        p = build(self.root)
        self.assertEqual(p["heldAssetCount"], 1)
        h = next(b for b in p["batches"] if b["provider"] == "laurenz/oracle_fdw")
        self.assertIn("EXISTING_P3_HOLD", h["records"][0]["blockers"])
        self.assertEqual(build(self.root, pg_filter="16")["totalCandidateAssets"], 1)

    def test_api_digest_is_not_independent(self):
        self.row["apiDigest"] = "sha256:" + "a" * 64
        self.save()
        record = build(self.root)["batches"][0]["records"][0]
        self.assertIsNone(record["originalSha256"])
        self.assertIn("INDEPENDENT_ORIGINAL_BYTES_NOT_PINNED", record["blockers"])

    def test_no_trust_elevation_even_with_candidate_fields(self):
        self.row.update(originalSha256="a"*64, originalBytes=22997,
            compatibilityVerified=True, dependenciesVerified=True,
            rightsReviewed=True, provenanceVerified=True, historical=False)
        self.save()
        p = build(self.root)
        self.assertEqual(p["admittedAssets"], 0)
        self.assertIn("INDEPENDENT_SIGNED_SOURCE_AUTHORIZATION_REQUIRED",
            p["batches"][0]["records"][0]["blockers"])

    def test_promotion_flips_and_duplicate_ids_denied(self):
        self.row["downloadAuthorized"] = True
        self.save()
        with self.assertRaises(Denied): build(self.root)
        self.row["downloadAuthorized"] = False
        self.inputs[1]["candidates"].append(copy.deepcopy(self.row))
        self.save()
        with self.assertRaises(Denied): build(self.root)

    def test_unknown_provider_and_mismatch_denied(self):
        self.row["sourceRepo"] = "pgextwin/build"
        self.save()
        with self.assertRaises(Denied): build(self.root)
        self.row["sourceRepo"] = "HypoPG/hypopg"
        self.row["extension"] = "evil"
        self.save()
        with self.assertRaises(Denied): build(self.root)

    def test_tampering_and_unbounded_batch_denied(self):
        with self.assertRaises(Denied): build(self.root, max_batch=21)
        with self.assertRaises(Denied): build(self.root, pg_filter="19")
        self.inputs[0]["publicationAuthorized"] = True
        self.save()
        with self.assertRaises(Denied): build(self.root)

    def test_duplicate_json_keys_denied(self):
        self.save()
        (self.root / INPUTS[0]).write_text('{"schemaVersion":"x","schemaVersion":"y"}')
        with self.assertRaises(Denied): build(self.root)


if __name__ == "__main__":
    unittest.main()
