"""Adversarial tests: upstream source equivalence is never distribution admission."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue112_pg_permissions_source_pins import audit, blob_sha, read_pinned, PINNED


def gitblob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


class SourcePinsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.old = Path(self.temp.name) / "old"
        self.new = Path(self.temp.name) / "new"
        self.old.mkdir()
        self.new.mkdir()
        self.data = {
            "LICENSE": b"Copyright fixture\npermission fixture\n",
            "pg_permissions.control": b"default_version = '1.4'\nrelocatable = false\n",
            "pg_permissions--1.3.sql": b"SELECT 1;\n",
        }
        self.pins = {k: gitblob(v) for k, v in self.data.items()}
        for root in (self.old, self.new):
            for name, content in self.data.items():
                (root / name).write_bytes(content)

    def test_matching_source_is_never_admitted(self):
        report = audit(self.old, self.new, self.pins)
        self.assertEqual(report["status"], "CANDIDATE_ONLY")
        self.assertEqual(report["sqlExtensionDefaultVersion"], "1.4")
        for field in ("publicGetAuthorized", "mirrorAuthorized",
                      "releaseAuthorized", "publisherAuthorized",
                      "producerProvenanceVerified", "originalZipLicenseNoticeVerified"):
            self.assertIs(report[field], False)

    def test_pinned_manifest_is_exactly_nine_real_source_files(self):
        self.assertEqual(len(PINNED), 9)
        self.assertEqual(PINNED["LICENSE"], "1fd282a61d03946e180a0b82a7c82d553e175db8")
        self.assertEqual(PINNED["pg_permissions.control"],
                         "18ec7b614454c98b3c33b1d8e7af84167fb6e624")

    def test_git_blob_algorithm(self):
        self.assertEqual(blob_sha(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")

    def test_newer_sql_mutation_denied(self):
        (self.new / "pg_permissions--1.3.sql").write_bytes(b"SELECT 2;\n")
        with self.assertRaisesRegex(ValueError, "pinned Git blob mismatch"):
            audit(self.old, self.new, self.pins)

    def test_notice_mutation_denied(self):
        (self.new / "LICENSE").write_bytes(b"copyright removed\n")
        with self.assertRaisesRegex(ValueError, "pinned Git blob mismatch"):
            audit(self.old, self.new, self.pins)

    def test_missing_notice_denied(self):
        (self.new / "LICENSE").unlink()
        with self.assertRaisesRegex(ValueError, "unexpected or missing"):
            audit(self.old, self.new, self.pins)

    def test_extra_installable_sql_denied(self):
        (self.new / "pg_permissions--9.9.sql").write_bytes(b"SELECT 9;")
        with self.assertRaisesRegex(ValueError, "unexpected or missing"):
            audit(self.old, self.new, self.pins)

    def test_bad_control_version_denied(self):
        data = b"default_version = '1.4.1'\n"
        (self.new / "pg_permissions.control").write_bytes(data)
        pins = dict(self.pins)
        pins["pg_permissions.control"] = gitblob(data)
        with self.assertRaisesRegex(ValueError, "pinned Git blob mismatch|default_version"):
            audit(self.old, self.new, pins)

    def test_nonexistent_root_denied(self):
        with self.assertRaisesRegex(ValueError, "missing or symlinked"):
            read_pinned(self.new / "missing", self.pins)

    def test_symlinked_source_denied(self):
        link = Path(self.temp.name) / "linked"
        try:
            link.symlink_to(self.new, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlink not supported by test filesystem")
        with self.assertRaisesRegex(ValueError, "symlinked"):
            audit(self.old, link, self.pins)

    def test_linked_license_denied(self):
        (self.new / "LICENSE").unlink()
        try:
            (self.new / "LICENSE").symlink_to(self.old / "LICENSE")
        except (OSError, NotImplementedError):
            self.skipTest("symlink not supported by test filesystem")
        with self.assertRaisesRegex(ValueError, "linked file"):
            audit(self.old, self.new, self.pins)

    def test_unsafe_pin_name_denied(self):
        pins = dict(self.pins)
        pins["../LICENSE"] = "a" * 40
        with self.assertRaisesRegex(ValueError, "unsafe pinned"):
            audit(self.old, self.new, pins)


if __name__ == "__main__":
    unittest.main()
