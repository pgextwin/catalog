"""Hostile offline tests for PGroonga original Actions outer-to-Release byte proof."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgroonga_actions_inner_bytes as evidence


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inner_fixture(pg):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"share/extension/pgroonga-pg{pg}.control",
                   "default_version = '4.1.0'\n")
    return stream.getvalue()


def outer_fixture(pg, target, *, inner=None, member=None, extra=False):
    inner = inner if inner is not None else inner_fixture(pg)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            member or f"pgroonga-4.1.0-postgresql-{pg}-x64.zip", inner)
        if extra:
            z.writestr("wrong-additional.zip", inner)
    data = target.read_bytes()
    return inner, (1500 + pg, len(data), sha(data))


class ActionsInnerEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.pg = 18
        self.outer = self.directory / "pgroonga-upstream-original-pg18.zip"
        self.inner, self.pin = outer_fixture(self.pg, self.outer)
        self.patches = [
            patch.dict(evidence.ARTIFACTS, {"18": self.pin}),
            patch.dict(evidence.PINS, {18: (len(self.inner), sha(self.inner))}),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_exact_outer_digest_and_inner_release_pin(self):
        row = evidence.verify_original_outer(self.pg, self.outer)
        self.assertTrue(row["actionsArtifactToReleaseByteIdentityVerified"])
        self.assertEqual(row["verifiedActionsOuterSha256"], self.pin[2])
        self.assertEqual(row["verifiedInnerSha256MatchesReleasePin"],
                         sha(self.inner))
        self.assertFalse(row["signedSourceInputToBinaryAttestationVerified"])
        self.assertFalse(row["historicalGroongaLatestZipDigestKnown"])
        final = evidence.report([row])
        self.assertTrue(all(value is False for value in evidence.DENY.values()))
        self.assertFalse(final["publicGetAuthorized"])
        self.assertFalse(final["publisherAuthorized"])

    def test_fake_outer_digest_even_if_inner_is_good_rejected(self):
        self.outer.write_bytes(self.outer.read_bytes() + b"surplus")
        with self.assertRaisesRegex(ValueError, "oversized"):
            evidence.verify_original_outer(self.pg, self.outer)
        self.outer.write_bytes(self.outer.read_bytes()[:-7])
        fake = (self.pin[0], self.pin[1], "0" * 64)
        with patch.dict(evidence.ARTIFACTS, {"18": fake}):
            with self.assertRaisesRegex(ValueError, "SHA256"):
                evidence.verify_original_outer(self.pg, self.outer)

    def test_inner_sha_drift_rejected_even_with_valid_outer_digest(self):
        fake_inner = self.inner[:-1] + bytes([self.inner[-1] ^ 1])
        _, new_pin = outer_fixture(self.pg, self.outer, inner=fake_inner)
        with patch.dict(evidence.ARTIFACTS, {"18": new_pin}):
            with self.assertRaisesRegex(ValueError, "differs"):
                evidence.verify_original_outer(self.pg, self.outer)

    def test_wrong_outer_member_and_extra_member_rejected(self):
        _, new_pin = outer_fixture(self.pg, self.outer,
                                   member="pgroonga-4.1.0-postgresql-17-x64.zip")
        with patch.dict(evidence.ARTIFACTS, {"18": new_pin}):
            with self.assertRaisesRegex(ValueError, "member paths"):
                evidence.verify_original_outer(self.pg, self.outer)
        _, new_pin = outer_fixture(self.pg, self.outer, extra=True)
        with patch.dict(evidence.ARTIFACTS, {"18": new_pin}):
            with self.assertRaisesRegex(ValueError, "member paths"):
                evidence.verify_original_outer(self.pg, self.outer)

    def test_inner_size_drift_rejected(self):
        with patch.dict(evidence.PINS, {18: (len(self.inner) + 1, sha(self.inner))}):
            with self.assertRaisesRegex(ValueError, "wrong-size"):
                evidence.verify_original_outer(self.pg, self.outer)

    def test_wrong_pg_and_nonexistent_archive_rejected(self):
        for invalid in (0, 13, 19, "18", None, True):
            with self.subTest(pg=invalid), self.assertRaises(ValueError):
                evidence.verify_original_outer(invalid, self.outer)
        with self.assertRaisesRegex(ValueError, "missing"):
            evidence.verify_original_outer(18, self.directory / "missing.zip")

    def test_symlink_and_broken_zip_rejected(self):
        link = self.directory / "alias.zip"
        try:
            link.symlink_to(self.outer)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(ValueError, "symlink"):
            evidence.verify_original_outer(18, link)
        self.outer.write_bytes(b"not a ZIP")
        with patch.dict(evidence.ARTIFACTS, {"18": (self.pin[0], 9, sha(b"not a ZIP"))}):
            with self.assertRaisesRegex(ValueError, "invalid outer ZIP"):
                evidence.verify_original_outer(18, self.outer)

    def test_five_major_cohort_no_cross_major_inheritance(self):
        rows = []
        for pg in sorted(evidence.PINS):
            path = self.directory / f"pgroonga-upstream-original-pg{pg}.zip"
            inner, pin = outer_fixture(pg, path)
            with patch.dict(evidence.ARTIFACTS, {str(pg): pin}), patch.dict(
                    evidence.PINS, {pg: (len(inner), sha(inner))}):
                rows.append(evidence.verify_original_outer(pg, path))
        out = evidence.report(rows[::-1])
        self.assertEqual([x["pgMajor"] for x in out["verified"]], [14, 15, 16, 17, 18])
        self.assertEqual(len({x["originalActionsArtifactId"] for x in rows}), 5)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evidence.report(rows + [rows[0]])

    def test_original_source_and_run_identity_is_not_signature(self):
        self.assertEqual(evidence.RUNS["windows"][:2], (37872644159, 1))
        self.assertEqual(len(evidence.ARTIFACTS), 5)
        self.assertEqual(evidence.COMMIT,
                         "47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc")
        self.assertFalse(evidence.DENY["signedHistoricalGroongaInputToBinaryAttestationVerified"])
        self.assertFalse(evidence.DENY["sourceSpecificOwnerSignedGetAdmissionVerified"])


if __name__ == "__main__":
    unittest.main()
