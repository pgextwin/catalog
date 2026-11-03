"""Read-only evidence reconciliation; no candidate can gain download authority."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import external_admission_preflight as p  # noqa: E402

PILOT = json.loads((ROOT / p.PILOT).read_text())


class AdmissionPreflightTests(unittest.TestCase):
    def test_actual_registry_coverage_and_two_original_byte_pilots(self):
        candidates = p.load_candidates()
        self.assertEqual(203, len(candidates))
        report = p.preflight(candidates, PILOT)
        self.assertEqual(203, report["candidates"])
        self.assertEqual(2, report["bytePilotsLinked"])
        self.assertEqual(203, report["blockedCandidates"])
        self.assertFalse(report["publicationAuthorized"])
        self.assertFalse(report["downloadAuthorized"])
        self.assertFalse(report["mirrorAuthorized"])
        self.assertEqual(198, report["missingGatesCount"]["fixed_upstream_source_commit"])
        self.assertEqual(201, report["missingGatesCount"]["independent_original_zip_byte_hash"])
        self.assertEqual(203, report["missingGatesCount"]["per_file_license_notices_and_direct_link_rights"])
        self.assertEqual(203, report["missingGatesCount"]["exact_pg_distribution_arch_and_abi_runtime"])
        self.assertEqual(203, report["missingGatesCount"]["formal_publisher_download_authorization"])
        self.assertEqual(203, len({(r["sourceRepo"], r["releaseId"], r["assetId"])
                                   for r in report["records"]}))
        matched = [r for r in report["records"] if r["reportedOriginalBytePilotSha256"]]
        self.assertEqual({"laurenz/oracle_fdw", "andreiramani/pgvector_pgsql_windows"},
                         {r["sourceRepo"] for r in matched})
        self.assertTrue(all(r["bytePilotScope"] == "BYTE_INTEGRITY_ONLY" and
                            r["downloadAuthorized"] is False and
                            "formal_publisher_download_authorization" in r["missingGates"]
                            for r in matched))

    def test_attestation_claim_not_upgraded_by_raw_byte_pilot(self):
        report = p.preflight(p.load_candidates(), PILOT)
        self.assertTrue(all("cryptographic_or_independently_approved_provenance"
                            in r["missingGates"] for r in report["records"]))

    def test_reject_pilot_wrong_asset_version_and_duplicate_id(self):
        candidates = p.load_candidates()
        bad = copy.deepcopy(PILOT)
        bad["results"][0]["assetId"] += 1
        with self.assertRaises(ValueError):
            p.preflight(candidates, bad)
        bad = copy.deepcopy(PILOT)
        bad["results"][0]["upstreamVersion"] = "0.0.1"
        with self.assertRaises(ValueError):
            p.preflight(candidates, bad)
        bad = copy.deepcopy(PILOT)
        bad["results"].append(copy.deepcopy(bad["results"][0]))
        with self.assertRaises(ValueError):
            p.preflight(candidates, bad)

    def test_mismatched_official_api_digest_fails_closed(self):
        candidates = copy.deepcopy(p.load_candidates())
        official = next(c for c in candidates if c["sourceRepo"] == "laurenz/oracle_fdw"
                        and c["assetId"] == 442625860)
        self.assertIsNotNone(official["apiDigest"])
        official["apiDigest"] = "sha256:" + "f" * 64
        with self.assertRaises(ValueError):
            p.preflight(candidates, PILOT)

    def test_metadata_cannot_launder_license_source_or_download(self):
        for field, value in (
            ("rightsReviewed", True),
            ("downloadAuthorized", True),
            ("verificationState", "verified"),
            ("originalSha256", "a" * 64),
            ("provenanceVerified", True),
            ("dependenciesVerified", True),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as folder:
                external = Path(folder) / "external"
                external.mkdir()
                for item in p.REGISTRIES:
                    source = json.loads((ROOT / item).read_text(encoding="utf-8"))
                    if item == p.REGISTRIES[0]:
                        source["candidates"][0][field] = value
                    (Path(folder) / item).write_text(
                        json.dumps(source), encoding="utf-8")
                with self.assertRaises(ValueError):
                    p.load_candidates(Path(folder))

    def test_byte_pilot_cannot_launder_signature_or_mirror(self):
        for field in ("signatureVerified", "licenseApproved", "abiApproved",
                      "provenanceVerified", "downloadAuthorized", "mirrorAuthorized"):
            bad = copy.deepcopy(PILOT)
            bad[field] = True
            with self.assertRaises(ValueError):
                p.preflight(p.load_candidates(), bad)

    def test_preflight_has_no_network_or_release_actions(self):
        source = (ROOT / "scripts/external_admission_preflight.py").read_text()
        self.assertNotIn("urllib", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("workflow_dispatch", source)
        self.assertNotIn("release/upload", source)



if __name__ == "__main__":
    unittest.main()
