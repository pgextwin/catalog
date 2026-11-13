"""Hostile no-network tests for PG18 OSGeo exact-original control inventory."""
import copy
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_osgeo_pg18_bundle_controls as target


class OriginalBundleControlTests(unittest.TestCase):
    def archive(self, members):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, contents in members:
                archive.writestr(name, contents)
        buffer.seek(0)
        return zipfile.ZipFile(buffer)

    def members(self):
        return [
            (target.ROOT + "share/extension/postgis.control",
             b"default_version = '3.7.0'\n"),
            (target.ROOT + "share/extension/pgrouting.control",
             b"# source is not attested\ndefault_version = '4.0.1'\n"),
            (target.ROOT + "extras/pg18/share/extension/h3.control",
             b"default_version = '4.5.0'\n"),
        ]

    def test_only_exact_control_members_are_observed_and_never_authorized(self):
        with self.archive(self.members()) as archive:
            receipt = target.inventory(archive)
        rows = {r["extension"]: r for r in receipt["componentObservations"]}
        self.assertEqual(len(rows), 14)
        self.assertTrue(rows["postgis"]["directInstallableControlObserved"])
        self.assertEqual(rows["pgrouting"]["observedControlMembers"][0]["declaredDefaultVersion"], "4.0.1")
        self.assertEqual(rows["h3"]["observedControlMembers"][0]["location"],
                         "NESTED_BUNDLE_CANDIDATE_ONLY")
        self.assertFalse(rows["h3"]["directInstallableControlObserved"])
        self.assertFalse(rows["pg_sphere"]["observedControlMembers"])
        self.assertEqual(receipt["observedComponentControlNames"], 3)
        self.assertTrue(receipt["memberPresenceIsNotCurrentSupportOrLicense"])
        self.assertTrue(all(receipt[field] is False for field in target.DENIALS))

    def test_spoofed_foreign_root_and_wrong_suffix_not_a_candidate(self):
        members = self.members()
        members.append(("other-bundle/share/extension/pg_sphere.control",
                        b"default_version = '99.0.0'"))
        members.append((target.ROOT + "share/extensions/pg_sphere.control",
                        b"default_version = '99.0.0'"))
        with self.archive(members) as archive:
            receipt = target.inventory(archive)
        rows = {r["extension"]: r for r in receipt["componentObservations"]}
        self.assertFalse(rows["pg_sphere"]["observedControlMembers"])

    def test_missing_root_or_pg_routing_rejected(self):
        with self.archive(self.members()[:1]) as archive:
            with self.assertRaisesRegex(ValueError, "Missing core"):
                target.inventory(archive)

    def test_duplicate_casefold_paths_rejected(self):
        members = self.members()
        members.append((target.ROOT + "share/extension/POSTGIS.control", b"empty"))
        with self.archive(members) as archive:
            with self.assertRaisesRegex(ValueError, "Duplicate casefolded"):
                target.inventory(archive)

    def test_malformed_control_is_not_promoted(self):
        mutations = [
            b"", b"X" * (target.MAX_CONTROL_BYTES + 1), b"\xff\xfe",
            b"default_version = '4.0.1'\n\x00",
            b"default_version = '4.0.1'\ndefault_version = '4.0.2'\n",
        ]
        for raw in mutations:
            members = self.members()
            members[1] = (members[1][0], raw)
            with self.subTest(bytes=len(raw)), self.archive(members) as archive:
                with self.assertRaises(ValueError):
                    target.inventory(archive)

    def test_unparseable_default_version_is_explicitly_unknown(self):
        members = self.members()
        members[1] = (members[1][0], b"default_version = '4.0.2dev'\n")
        with self.archive(members) as archive:
            result = target.inventory(archive)
        row = next(r for r in result["componentObservations"] if r["extension"] == "pgrouting")
        self.assertIsNone(row["observedControlMembers"][0]["declaredDefaultVersion"])

    def test_exact_source_no_redirect_and_sha_size_are_mandatory(self):
        size, sha = target.EXPECTED_SIZE, target.EXPECTED_SHA
        with mock.patch.object(target, "read_original", return_value=(size - 1, sha)) as get, \
             mock.patch.object(target, "verified_local_zip") as verify, \
             mock.patch.object(target, "inventory") as inspect:
            with self.assertRaisesRegex(ValueError, "SHA256/size"):
                target.review_original(opener=object())
            self.assertEqual(get.call_args.args[0], target.ORIGIN)
            verify.assert_not_called()
            inspect.assert_not_called()

    def test_digest_mismatch_not_accepted(self):
        with mock.patch.object(target, "read_original",
                               return_value=(target.EXPECTED_SIZE, "0" * 64)), \
             mock.patch.object(target, "verified_local_zip") as verify:
            with self.assertRaisesRegex(ValueError, "SHA256/size"):
                target.review_original(opener=object())
            verify.assert_not_called()

    def test_no_redirect_by_default_and_positive_authority_rejected(self):
        receipt = {"status": "CANDIDATE_ONLY"}
        receipt.update({flag: False for flag in target.DENIALS})
        for mutation in ("publicGetAuthorized", "mirrorAuthorized", "ownerSignedAdmission"):
            escalated = copy.deepcopy(receipt)
            escalated[mutation] = True
            with self.subTest(mutation=mutation), \
                 mock.patch.object(target.urllib.request, "build_opener", return_value=object()) as opener, \
                 mock.patch.object(target, "read_original",
                                   return_value=(target.EXPECTED_SIZE, target.EXPECTED_SHA)), \
                 mock.patch.object(target, "verified_local_zip"), \
                 mock.patch.object(target.zipfile, "ZipFile"), \
                 mock.patch.object(target, "inventory", return_value=escalated):
                with self.assertRaisesRegex(ValueError, "Unauthorized positive"):
                    target.review_original()
                self.assertIsInstance(opener.call_args.args[0], target.NoRedirect)


if __name__ == "__main__":
    unittest.main()
