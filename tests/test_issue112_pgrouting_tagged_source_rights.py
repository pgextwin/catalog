#!/usr/bin/env python3
"""Hostile no-network tests for pgRouting source-only license evidence."""
import base64
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgrouting_tagged_source_rights as target
from issue112_osgeo_tagged_source_rights import git_blob_sha


class FakeGitHub:
    def __init__(self, release_tag=target.TAG):
        self.release_tag = release_tag
        self.tag_object = target.TAG_OBJECT_401 if release_tag == target.TAG_401 else target.TAG_OBJECT
        self.commit = target.COMMIT_401 if release_tag == target.TAG_401 else target.COMMIT
        markers = dict(target.SOURCE_MARKERS)
        if release_tag == target.TAG_401:
            markers["CMakeLists.txt"] = tuple(
                x.replace("VERSION 4.0.0", "VERSION 4.0.1")
                for x in markers["CMakeLists.txt"])
        self.files = {
            path: ("\n".join(parts) + "\n").encode("utf-8")
            for path, parts in markers.items()
        }
        self.wrong_ref = False
        self.wrong_tag_commit = False
        self.wrong_path = False
        self.wrong_blob = False
        self.forced_sha = {}

    def pins(self):
        return {path: git_blob_sha(data) for path, data in self.files.items()}

    def get(self, url):
        if url == target.API + "/git/ref/tags/" + self.release_tag:
            return {
                "ref": "refs/tags/" + ("v0.0.0" if self.wrong_ref else self.release_tag),
                "object": {"sha": self.tag_object, "type": "tag",
                           "url": target.API + "/git/tags/" + self.tag_object},
            }
        if url == target.API + "/git/tags/" + self.tag_object:
            return {"tag": self.release_tag, "object": {"type": "commit",
                    "sha": "f" * 40 if self.wrong_tag_commit else self.commit}}
        for path, body in self.files.items():
            if url == target.API + "/contents/" + path + "?ref=" + self.commit:
                return {
                    "path": path + ".tampered" if self.wrong_path else path,
                    "sha": "f" * 40 if self.wrong_blob else self.forced_sha.get(path, self.pins()[path]),
                    "encoding": "base64",
                    "content": base64.b64encode(body).decode("ascii"),
                }
        raise AssertionError("Unexpected network path: " + url)


class PgRoutingSourceRightsTests(unittest.TestCase):
    def test_expected_pins_and_strict_denials(self):
        fake = FakeGitHub()
        result = target.audit(fake.get, expected_blobs=fake.pins())
        self.assertEqual(result["scope"], target.SOURCE_SCOPE)
        self.assertEqual(result["tagCommit"], target.COMMIT)
        self.assertEqual(set(result["sourceGitBlobsSha1"]), set(target.BLOBS))
        self.assertIn("Boost-1.0", result["licenseObservations"]["boost"])
        self.assertIn("MIT-X", result["licenseObservations"]["iMaptools"])
        self.assertEqual(result["candidateOsgeoZip"]["dllBasename"], "libpgrouting-4.0.dll")
        for key, value in result.items():
            if key.endswith("Verified") or key.endswith("Authorized"):
                self.assertIs(value, False, key)

    def test_mismatched_tag_ref_denied(self):
        fake = FakeGitHub()
        fake.wrong_ref = True
        with self.assertRaisesRegex(ValueError, "tag ref"):
            target.audit(fake.get, expected_blobs=fake.pins())

    def test_mismatched_tag_commit_denied(self):
        fake = FakeGitHub()
        fake.wrong_tag_commit = True
        with self.assertRaisesRegex(ValueError, "tag-to-commit"):
            target.audit(fake.get, expected_blobs=fake.pins())

    def test_path_and_sha_substitution_denied(self):
        fake = FakeGitHub()
        fake.wrong_path = True
        with self.assertRaisesRegex(ValueError, "path/blob"):
            target.audit(fake.get, expected_blobs=fake.pins())
        fake.wrong_path = False
        fake.wrong_blob = True
        with self.assertRaisesRegex(ValueError, "path/blob"):
            target.audit(fake.get, expected_blobs=fake.pins())

    def test_source_tampering_under_old_digest_denied(self):
        fake = FakeGitHub()
        old = fake.pins()
        fake.files["README.md"] += b"forged release claims"
        fake.forced_sha["README.md"] = old["README.md"]
        with self.assertRaisesRegex(ValueError, "Invalid pinned pgRouting source"):
            target.audit(fake.get, expected_blobs=old)

    def test_missing_boost_or_mit_notice_claim_denied(self):
        for path, marker in (
                ("README.md", target.SOURCE_MARKERS["README.md"][2]),
                ("BOOST_LICENSE_1_0.txt", target.SOURCE_MARKERS["BOOST_LICENSE_1_0.txt"][0])):
            fake = FakeGitHub()
            fake.files[path] = fake.files[path].replace(marker.encode("utf-8"), b"redacted")
            with self.assertRaisesRegex(ValueError, "license/build claim absent"):
                target.audit(fake.get, expected_blobs=fake.pins())

    def test_missing_or_extra_pins_denied(self):
        fake = FakeGitHub()
        pins = fake.pins()
        pins.pop("README.md")
        with self.assertRaisesRegex(ValueError, "pinned source inventory"):
            target.audit(fake.get, expected_blobs=pins)
        pins = fake.pins()
        pins["unexpected"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "pinned source inventory"):
            target.audit(fake.get, expected_blobs=pins)

    def test_expected_content_enforces_byte_bound(self):
        fake = FakeGitHub()
        fake.files["README.md"] += b"x" * (target.MAX_SOURCE_FILE + 1)
        with self.assertRaisesRegex(ValueError, "Invalid pinned pgRouting source"):
            target.audit(fake.get, expected_blobs=fake.pins())

    def test_no_redirect_or_untrusted_endpoint(self):
        with self.assertRaisesRegex(ValueError, "Unauthorized source endpoint"):
            target.source_get_json("https://example.invalid/unknown")
        with self.assertRaisesRegex(ValueError, "Redirect rejected"):
            target.RejectRedirect().redirect_request(None, None, None, 302, None, None)

    def test_401_matches_observed_extension_version_but_not_binary_attestation(self):
        fake = FakeGitHub(target.TAG_401)
        result = target.audit(fake.get, expected_blobs=fake.pins(),
                              release_tag=target.TAG_401)
        self.assertEqual(result["tag"], "v4.0.1")
        self.assertEqual(result["tagCommit"], target.COMMIT_401)
        self.assertEqual(result["candidateOsgeoZip"]["observedInstalledVersionFromPriorWindowsSql"], "4.0.1")
        self.assertNotEqual(result["sourceGitBlobsSha1"]["CMakeLists.txt"],
                            target.BLOBS["CMakeLists.txt"])
        for key, value in result.items():
            if key.endswith("Verified") or key.endswith("Authorized"):
                self.assertIs(value, False, key)

    def test_401_wrong_tag_and_commit_denied(self):
        for flag, error in (("wrong_ref", "tag ref"), ("wrong_tag_commit", "tag-to-commit")):
            fake = FakeGitHub(target.TAG_401)
            setattr(fake, flag, True)
            with self.assertRaisesRegex(ValueError, error):
                target.audit(fake.get, expected_blobs=fake.pins(),
                             release_tag=target.TAG_401)

    def test_401_wrong_cmake_claim_denied(self):
        fake = FakeGitHub(target.TAG_401)
        fake.files["CMakeLists.txt"] = fake.files["CMakeLists.txt"].replace(
            b"VERSION 4.0.1", b"VERSION 4.0.0")
        with self.assertRaisesRegex(ValueError, "license/build claim absent"):
            target.audit(fake.get, expected_blobs=fake.pins(),
                         release_tag=target.TAG_401)

    def test_401_rejects_old_cmake_pin_and_unlisted_tag(self):
        fake = FakeGitHub(target.TAG_401)
        pins = fake.pins()
        pins["CMakeLists.txt"] = target.BLOBS["CMakeLists.txt"]
        with self.assertRaisesRegex(ValueError, "path/blob"):
            target.audit(fake.get, expected_blobs=pins,
                         release_tag=target.TAG_401)
        with self.assertRaisesRegex(ValueError, "Unrecognized pgRouting release tag"):
            target.audit(fake.get, release_tag="v5.0.0")


if __name__ == "__main__":
    unittest.main()
