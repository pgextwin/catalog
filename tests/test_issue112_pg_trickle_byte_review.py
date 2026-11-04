"""Offline hostile tests for pinned, private pg_trickle original ZIP review."""
import copy
import importlib.util
import io
from pathlib import Path
import struct
import sys
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pg_trickle_byte_review", ROOT / "scripts/issue112-pg-trickle-byte-review.py")
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


def fake_pe(machine=0x8664, magic=0x20B):
    blob = bytearray(512)
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x80)
    blob[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", blob, 0x84, machine)
    struct.pack_into("<H", blob, 0x98, magic)
    return bytes(blob)


def archive(dll=None, notice=True, extra=()):
    output = io.BytesIO()
    base = "pg_trickle-0.108.3-pg18-windows-amd64/"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(base + "lib/pg_trickle.dll", fake_pe() if dll is None else dll)
        z.writestr(base + "extension/pg_trickle.control", "default_version='0.108.3'")
        z.writestr(base + "extension/pg_trickle--0.108.3.sql", "-- synthetic")
        if notice:
            z.writestr(base + "LICENSE", "test license")
        for path, data in extra:
            z.writestr(path, data)
    return output.getvalue()


def metadata():
    return {
        "tag_name": review.TAG, "id": review.RELEASE_ID,
        "draft": False, "prerelease": False,
        "assets": [{"id": review.ASSET_ID, "name": review.ASSET,
                    "size": review.SIZE, "digest": "sha256:" + review.DIGEST,
                    "state": "uploaded", "browser_download_url": review.URL}],
    }


class PrivateByteReviewTests(unittest.TestCase):
    def test_expected_archive_inspects_pe_crc_notices_without_authority(self):
        info = review.examine_package(archive())
        self.assertEqual("AMD64_PE32_PLUS_HEADER_ONLY", info["peCheck"])
        self.assertEqual(1, info["sqlFiles"])
        self.assertEqual(4, info["zipMembers"])
        self.assertEqual(1, len(info["packageNoticeMembers"]))

    def test_missing_notice_does_not_imply_license_approval(self):
        info = review.examine_package(archive(notice=False))
        self.assertEqual([], info["packageNoticeMembers"])

    def test_wrong_pe_machine_rejected(self):
        with self.assertRaises(ValueError):
            review.examine_package(archive(dll=fake_pe(machine=0x14c)))
        with self.assertRaises(ValueError):
            review.examine_package(archive(dll=fake_pe(magic=0x10b)))
        with self.assertRaises(ValueError):
            review.examine_package(archive(dll=b"ELFnot-a-dll"))

    def test_traversal_and_case_duplicate_rejected(self):
        with self.assertRaises(ValueError):
            review.examine_package(archive(extra=[("../escape.dll", b"evil")]))
        with self.assertRaises(ValueError):
            review.examine_package(archive(
                extra=[("PG_TRICKLE-0.108.3-PG18-WINDOWS-AMD64/lib/PG_TRICKLE.DLL",
                        fake_pe())]))

    def test_wrong_pinned_release_digest_or_source_commit_rejected(self):
        expected_ref = {"object": {"type": "commit", "sha": review.TAG_SHA}}
        review.assert_release_identity(metadata(), expected_ref)
        altered = metadata()
        altered["assets"][0]["digest"] = "sha256:" + ("0" * 64)
        with self.assertRaises(ValueError):
            review.assert_release_identity(altered, expected_ref)
        altered = metadata()
        altered["assets"][0]["browser_download_url"] = "https://evil.invalid/a.zip"
        with self.assertRaises(ValueError):
            review.assert_release_identity(altered, expected_ref)
        with self.assertRaises(ValueError):
            review.assert_release_identity(metadata(),
                                           {"object": {"type": "commit", "sha": "0" * 40}})

    def test_no_user_download_or_publication_codepath(self):
        source = (ROOT / "scripts/issue112-pg-trickle-byte-review.py").read_text()
        self.assertNotIn("workflow_dispatch", source)
        self.assertNotIn("releases/upload", source)
        self.assertNotIn("POST", source)
        self.assertNotIn("subprocess", source)


if __name__ == "__main__":
    unittest.main()
