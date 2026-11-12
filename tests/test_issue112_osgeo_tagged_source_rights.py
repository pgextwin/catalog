#!/usr/bin/env python3
"""Hostile offline tests for immutable source-license evidence; zero network calls."""
import base64
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_osgeo_tagged_source_rights as audit


class FakeGitHub:
    def __init__(self):
        self.source = {
            "LICENSE.TXT": "\n".join(audit.LICENSE_MARKERS.values()),
            "COPYING": "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n",
            "ci/winnie/package_postgis.sh": "\n".join(audit.PACKAGE_MARKERS),
            "ci/winnie/winnie_common.sh": "\n".join(audit.COMMON_MARKERS),
        }
        self.wrong_ref = False
        self.wrong_commit = False
        self.forged_file_sha = False
        self.wrong_path = False
        self.override_sha = {}

    def expected(self):
        return {p: audit.git_blob_sha(v.encode("utf-8")) for p, v in self.source.items()}

    def get(self, url):
        if url == audit.API + "/git/ref/tags/" + audit.TAG:
            return {
                "ref": "refs/tags/" + ("3.7.0-forged" if self.wrong_ref else audit.TAG),
                "object": {"sha": audit.TAG_OBJECT, "type": "tag",
                           "url": audit.API + "/git/tags/" + audit.TAG_OBJECT},
            }
        if url == audit.API + "/git/tags/" + audit.TAG_OBJECT:
            return {"tag": audit.TAG, "object": {
                "type": "commit", "sha": "f" * 40 if self.wrong_commit else audit.COMMIT,
            }}
        for path, text in self.source.items():
            if url == audit.API + "/contents/" + path + "?ref=" + audit.COMMIT:
                return {"path": path + ".forged" if self.wrong_path else path,
                        "sha": "f" * 40 if self.forged_file_sha else self.override_sha.get(path, self.expected()[path]),
                        "encoding": "base64",
                        "content": base64.b64encode(text.encode("utf-8")).decode("ascii")}
        raise AssertionError("Unexpected network URL: " + url)


class SourceRightsTests(unittest.TestCase):
    def test_exact_source_reads_are_deny_only(self):
        github = FakeGitHub()
        report = audit.audit(github.get, expected_blobs=github.expected())
        self.assertEqual(report["tagTargetCommit"], audit.COMMIT)
        self.assertEqual(set(report["sourceBlobSha1"]), set(audit.BLOBS))
        self.assertEqual(set(report["taggedSourceLicenseStatements"]),
                         {"PostGIS", "PROJ", "GEOS", "LibXML", "GDAL", "SFCGAL", "CGAL"})
        self.assertTrue(report["winnieBuildDependencyVersionOverridesPossible"])
        self.assertEqual(report["scope"], "TAGGED_SOURCE_REFERENCE_ONLY_NOT_ACTUAL_PRODUCER")
        for key, value in report.items():
            if key.endswith("Verified") or key.endswith("Authorized") or key == "newScopedOwnerSignedAdmission":
                self.assertIs(value, False, key)

    def test_wrong_tag_name_denied(self):
        github = FakeGitHub()
        github.wrong_ref = True
        with self.assertRaisesRegex(ValueError, "tag ref"):
            audit.audit(github.get, expected_blobs=github.expected())

    def test_wrong_tag_commit_denied(self):
        github = FakeGitHub()
        github.wrong_commit = True
        with self.assertRaisesRegex(ValueError, "target commit"):
            audit.audit(github.get, expected_blobs=github.expected())

    def test_source_blob_sha_and_path_substitution_denied(self):
        github = FakeGitHub()
        github.forged_file_sha = True
        with self.assertRaisesRegex(ValueError, "blob identity"):
            audit.audit(github.get, expected_blobs=github.expected())
        github.forged_file_sha = False
        github.wrong_path = True
        with self.assertRaisesRegex(ValueError, "blob identity"):
            audit.audit(github.get, expected_blobs=github.expected())

    def test_source_body_modified_under_unchanged_blob_denied(self):
        github = FakeGitHub()
        original = github.expected()
        github.override_sha["LICENSE.TXT"] = original["LICENSE.TXT"]
        github.source["LICENSE.TXT"] += "\nInjected copy after original hash."
        with self.assertRaisesRegex(ValueError, "blob content"):
            audit.audit(github.get, expected_blobs=original)

    def test_missing_explicit_license_declaration_stays_denied(self):
        github = FakeGitHub()
        github.source["LICENSE.TXT"] = github.source["LICENSE.TXT"].replace(
            audit.LICENSE_MARKERS["GEOS"], "GEOS terms missing")
        with self.assertRaisesRegex(ValueError, "statement missing"):
            audit.audit(github.get, expected_blobs=github.expected())

    def test_missing_winnie_dependent_library_copy_stays_denied(self):
        github = FakeGitHub()
        github.source["ci/winnie/package_postgis.sh"] = github.source[
            "ci/winnie/package_postgis.sh"].replace("libcrypto-3-x64.dll", "")
        with self.assertRaisesRegex(ValueError, "statement missing"):
            audit.audit(github.get, expected_blobs=github.expected())

    def test_unrecognized_path_or_digest_inventory_denied(self):
        github = FakeGitHub()
        forged = dict(github.expected())
        forged["forged.txt"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "pin inventory"):
            audit.audit(github.get, expected_blobs=forged)

    def test_http_redirect_is_not_allowed(self):
        with self.assertRaisesRegex(ValueError, "Redirect rejected"):
            audit.RejectRedirect().redirect_request(None, None, None, 302, None, None)


if __name__ == "__main__":
    unittest.main()
