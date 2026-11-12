"""Offline hostile regression for the nonpublishing TimescaleDB legal/provenance intake."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.issue112_timescaledb_rights_gate import (
    ROOT, LEDGER_PATH, BASELINE_PATH, strict_json, validate,
)


class TimescaleDbRightsGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = strict_json(ROOT / LEDGER_PATH)
        cls.baseline = strict_json(ROOT / BASELINE_PATH)

    def changed(self, fn):
        clone = copy.deepcopy(self.ledger)
        fn(clone)
        with self.assertRaises(ValueError):
            validate(clone, self.baseline)

    def test_all_existing_evidence_pins_are_read_only_and_denied(self):
        self.assertTrue(validate(self.ledger, self.baseline))
        self.assertEqual(
            [x["pgMajor"] for x in self.ledger["windowsAssets"]],
            ["16", "17", "18"],
        )
        self.assertEqual(
            [x["originalBytes"] for x in self.ledger["windowsAssets"]],
            [9537404, 9537297, 9538882],
        )
        self.assertEqual(self.ledger["permissions"],
                         {"publicGet": False, "mirror": False,
                          "release": False, "publish": False})

    def test_do_not_conflate_legal_source_claims_with_binary_clearance(self):
        self.changed(lambda x: x["sourceLicenseScopes"][1].update(
            binaryAttribution="VERIFIED"))
        self.changed(lambda x: x["licenseReview"].update(
            specificUseAndTermsCleared=True))
        self.changed(lambda x: x["licenseReview"].update(
            allThirdPartyNoticesCleared=True))
        self.changed(lambda x: x["upstream"]["documents"].update(
            {"tsl/LICENSE-TIMESCALE": "0" * 40}))
        self.changed(lambda x: x["licenseReview"].update(
            timescaleClauses=["2.1(c)"]))

    def test_missing_provenance_and_owner_admission_fail_closed(self):
        for name in ("exactBinaryComponentToLicenseMapping",
                     "bundledLicenseNoticeCompleteness",
                     "runtimeAndBundledDependencyClosure",
                     "upstreamReleaseSourceToBinaryProvenance",
                     "producerAuthorizationForPgextwinDelivery"):
            with self.subTest(gate=name):
                self.changed(lambda x, n=name: x["evidence"].update({n: "PASS"}))
        self.changed(lambda x: x["evidence"].update(
            newSourceSpecificOwnerSignedAdmission="PASS"))
        for permission in ("publicGet", "mirror", "release", "publish"):
            with self.subTest(permission=permission):
                self.changed(lambda x, key=permission: x["permissions"].update({key: True}))

    def test_original_release_identity_and_pg_matrix_cannot_be_invented(self):
        self.changed(lambda x: x["upstream"].update(releaseId=418582852))
        self.changed(lambda x: x["windowsAssets"][0].update(pgMajor="15"))
        self.changed(lambda x: x["windowsAssets"][0].update(assetId=659788300))
        self.changed(lambda x: x["windowsAssets"][1].update(originalSha256="0" * 64))
        self.changed(lambda x: x["windowsAssets"].append(
            copy.deepcopy(x["windowsAssets"][0])))
        self.changed(lambda x: x.update(scope="PUBLIC_COMPLETE"))

    def test_strict_json_rejects_duplicate_keys_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            p = root / "hostile.json"
            p.write_text('{"publish":false,"publish":true}', encoding="utf-8")
            with self.assertRaises(ValueError):
                strict_json(p)
            p.unlink()
            p.symlink_to(ROOT / LEDGER_PATH)
            with self.assertRaises(ValueError):
                strict_json(p)


if __name__ == "__main__":
    unittest.main()
