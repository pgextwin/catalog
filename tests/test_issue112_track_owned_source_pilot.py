"""Offline hostile tests: new local source-owned pilot is never Cybertec admission."""
from io import BytesIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_track_owned_source_pilot as pilot

LICENSE = (b"Copyright (c) 2015-2023, Julien Rouhaud\n"
           b"Permission granted provided that the above copyright notice is reproduced\n")

def fixture(base):
    expected = {}
    for name in pilot.BLOBS:
        if name == "LICENSE":
            contents = LICENSE
        elif name == "pg_track_settings.control":
            contents = b"default_version = '2.1.2'\nrelocatable = false\n"
        else:
            contents = ("-- fixture for " + name + "\n").encode()
        (base / name).write_bytes(contents)
        expected[name] = pilot.git_blob(contents)
    return expected

class SourceOwnedPilotTests(unittest.TestCase):
    def test_exact_pins_are_git_blob_format(self):
        self.assertEqual(len(pilot.BLOBS), 14)
        self.assertTrue(all(len(blob) == 40 and all(ch in "0123456789abcdef" for ch in blob)
                            for blob in pilot.BLOBS.values()))
        self.assertEqual(pilot.SOURCE_SHA, "36a23f3c6d684c40140da1a24b1c3ee0e707b77a")

    def test_private_five_major_reproducible_rights_included(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pins = fixture(base)
            hashes = []
            for pg in pilot.MAJORS:
                raw, receipt = pilot.build_bytes(base, pg, blobs=pins, require_commit=False)
                again, _ = pilot.build_bytes(base, pg, blobs=pins, require_commit=False)
                self.assertEqual(raw, again)
                self.assertTrue(pilot.inspect_bytes(raw, pilot.exact_source(base, pins, False), pg))
                with zipfile.ZipFile(BytesIO(raw)) as archive:
                    self.assertEqual(archive.read("LICENSE"), LICENSE)
                    meta = json.loads(archive.read("SOURCE-INPUTS.json"))
                    self.assertEqual(meta["upstreamCommit"], pilot.SOURCE_SHA)
                    self.assertEqual(meta["postgresqlMajor"], pg)
                    self.assertTrue(meta["rightsNoticeIncluded"])
                    self.assertTrue(all(meta[k] is False for k in (
                        "cybertecProducerAttestation", "independentSignatureVerified",
                        "downloadAuthorized", "mirrorAuthorized", "releaseAuthorized",
                        "publisherAuthorized")))
                    self.assertEqual(len(archive.namelist()), 15)
                self.assertEqual(receipt["status"], "CANDIDATE_ONLY")
                hashes.append(raw)
            self.assertEqual(len(set(hashes)), 5)

    def test_reject_wrong_major_and_missing_modified_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pins = fixture(base)
            with self.assertRaisesRegex(ValueError, "unsupported PostgreSQL"):
                pilot.build_bytes(base, "19", blobs=pins, require_commit=False)
            target = base / "pg_track_settings--2.1.2.sql"
            target.write_bytes(b"-- malicious alteration")
            with self.assertRaisesRegex(ValueError, "Git blob pin mismatch"):
                pilot.build_bytes(base, "18", blobs=pins, require_commit=False)
            target.unlink()
            with self.assertRaisesRegex(ValueError, "missing or linked"):
                pilot.build_bytes(base, "18", blobs=pins, require_commit=False)

    def test_reject_symlink_and_license_modification(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pins = fixture(base)
            (base / "LICENSE").write_bytes(b"License deleted")
            with self.assertRaisesRegex(ValueError, "Git blob pin mismatch"):
                pilot.exact_source(base, pins, False)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pins = fixture(base)
            target = base / "pg_track_settings--2.1.2.sql"
            target.unlink()
            try:
                target.symlink_to(base / "LICENSE")
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(ValueError, "missing or linked"):
                pilot.exact_source(base, pins, False)

    def test_bad_git_commit_is_not_a_pinned_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pins = fixture(base)
            fake = mock.Mock(returncode=0, stdout="0" * 40)
            with mock.patch.object(pilot.subprocess, "run", return_value=fake):
                with self.assertRaisesRegex(ValueError, "pinned upstream commit"):
                    pilot.exact_source(base, pins, True)
            with mock.patch.object(pilot.subprocess, "run",
                                   return_value=mock.Mock(returncode=1, stdout="")):
                with self.assertRaisesRegex(ValueError, "pinned upstream commit"):
                    pilot.exact_source(base, pins, True)

    def test_reject_poisoned_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pins = fixture(base)
            files = pilot.exact_source(base, pins, False)
            raw, _ = pilot.build_bytes(base, "14", blobs=pins, require_commit=False)
            with zipfile.ZipFile(BytesIO(raw)) as original:
                members = {n: original.read(n) for n in original.namelist()}
            forged = json.loads(members["SOURCE-INPUTS.json"])
            forged["releaseAuthorized"] = True
            members["SOURCE-INPUTS.json"] = pilot.encode_json(forged)
            stream = BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                for k, v in sorted(members.items()):
                    archive.writestr(k, v)
            with self.assertRaisesRegex(ValueError, "archive content mismatch"):
                pilot.inspect_bytes(stream.getvalue(), files, "14")

    def test_unrecognized_pin_map_cannot_add_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pins = fixture(base)
            pins["evil/README"] = "0" * 40
            with self.assertRaisesRegex(ValueError, "unexpected source member set"):
                pilot.build_bytes(base, "14", blobs=pins, require_commit=False)

if __name__ == "__main__":
    unittest.main()
