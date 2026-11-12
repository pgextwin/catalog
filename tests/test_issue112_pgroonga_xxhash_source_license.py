"""Fail-closed offline controls for original xxHash source/NOTICE-gap joins."""
import base64
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgroonga_xxhash_source_license as audit


WRAP = """[wrap-file]
directory = xxHash-0.8.3
source_url = https://github.com/Cyan4973/xxHash/archive/v0.8.3.tar.gz
source_filename = xxHash-0.8.3.tar.gz
source_hash = aae608dfe8213dfd05d909a57718ef82f30722c392344583d3f39050c7f29a80
patch_filename = xxhash_0.8.3-2_patch.zip
patch_url = https://wrapdb.mesonbuild.com/v2/xxhash_0.8.3-2/get_patch
patch_hash = c7f78fc2d08ec21ff1bae928d7bdcddb42713a07d9d973a885c59ea7f8cf6bc8
source_fallback_url = https://github.com/mesonbuild/wrapdb/releases/download/xxhash_0.8.3-2/xxHash-0.8.3.tar.gz
wrapdb_version = 0.8.3-2

[provide]
libxxhash = xxhash_dep
"""
LEGAL = """xxHash Library
Copyright (c) 2012-2021 Yann Collet
BSD 2-Clause License
Redistributions of source code must retain the above copyright notice
Redistributions in binary form must reproduce the above copyright notice
in documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"""


def blob(text):
    raw = text.encode("utf-8")
    sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + bytes([0]) + raw).hexdigest()
    return sha, {"sha": sha, "encoding": "base64",
                 "content": base64.b64encode(raw).decode()}


def tag():
    return {"ref": "refs/tags/v0.8.3",
            "object": {"type": "commit", "sha": audit.XXHASH_COMMIT}}


def graph_fixture():
    return {
        "parsedPeMembers": 43, "namedLegalDocuments": 25,
        "notBundledImportNames": [{"name": n} for n in audit.EXPECTED_EXTERNAL],
        "ambiguousBundledImportNames": [],
        "missingNamedNoticeAtOwnBinary": sorted(audit.XXHASH_BINARIES),
        "staticReachableMissingNamedNoticeConsumers": sorted(audit.XXHASH_AFFECTED),
        "perBinaryGraph": [{"sha256": "a" * 64}] * 43,
    }


class SourceLicenseTests(unittest.TestCase):
    def test_pinned_source_receipts_preserve_binary_notice_denials(self):
        wrap_sha, w = blob(WRAP)
        license_sha, lic = blob(LEGAL)
        with patch.object(audit, "WRAP_BLOB", wrap_sha), patch.object(
                audit, "LICENSE_BLOB", license_sha):
            result = audit.source_legal_receipts(tag(), w, lic)
        self.assertTrue(result["sourceLicenseTextVerified"])
        self.assertTrue(result["binaryRedistributionRequiresNotice"])
        self.assertEqual(result["declaredVersion"], "0.8.3")
        self.assertFalse(result["releasedXxhashBinaryBoundToThisSource"])
        self.assertFalse(result["historicalMutableGroongaInputDigestVerified"])

    def test_tag_substitution_and_unsigned_source_ambiguity_denied(self):
        forged = tag()
        forged["object"]["sha"] = "b" * 40
        with self.assertRaises(ValueError):
            audit.check_tag(forged)
        forged = tag()
        forged["object"]["type"] = "tag"
        with self.assertRaises(ValueError):
            audit.check_tag(forged)

    def test_git_content_tamper_wrong_sha_and_length_denied(self):
        sha, valid = blob(LEGAL)
        self.assertEqual(audit.decode_pinned_blob(valid, sha, 10000), LEGAL)
        for mutated in (
                {**valid, "content": base64.b64encode(b"forged").decode()},
                {**valid, "sha": "a" * 40},
                {**valid, "encoding": "utf-8"},
                valid):
            if mutated is valid:
                with self.assertRaises(ValueError):
                    audit.decode_pinned_blob(valid, sha, 10)
            else:
                with self.assertRaises(ValueError):
                    audit.decode_pinned_blob(mutated, sha, 10000)

    def test_missing_legal_obligation_or_wrap_pin_denied(self):
        audit.check_wrap(WRAP)
        audit.check_license(LEGAL)
        with self.assertRaises(ValueError):
            audit.check_license(LEGAL.replace("in binary form", "in object form"))
        with self.assertRaises(ValueError):
            audit.check_wrap(WRAP.replace(audit.SOURCE_SHA256, "0" * 64))
        with self.assertRaises(ValueError):
            audit.check_wrap(WRAP.replace("0.8.3-2", "0.8.3-3"))

    def test_actual_22_name_triage_is_not_loader_proof(self):
        self.assertEqual(len(audit.EXPECTED_EXTERNAL), 22)
        self.assertEqual(sum(audit.classify_import_name(n) ==
                             "WINDOWS_CRT_API_SET_NAME_ONLY"
                             for n in audit.EXPECTED_EXTERNAL), 11)
        self.assertEqual(sum(audit.classify_import_name(n) ==
                             "VC_RUNTIME_DLL_NAME_ONLY"
                             for n in audit.EXPECTED_EXTERNAL), 4)
        self.assertEqual(audit.classify_import_name("evil.dll"),
                         "UNCLASSIFIED_UNVERIFIED")

    def test_original_graph_must_keep_exact_22_and_three_notice_gaps(self):
        good = graph_fixture()
        with patch.object(audit, "audit_members", return_value={}), patch.object(
                audit, "inspect_archive", return_value={}), patch.object(
                audit, "graph", return_value=good):
            result = audit.review_original(18, Path("unused"), {})
            self.assertEqual(result["externalImportNamesObserved"], 22)
            self.assertFalse(result["namedUpstreamLicensePresentInOriginalZip"])
            self.assertFalse(result["publicGetAuthorized"])
            self.assertFalse(result["publisherAuthorized"])
            good["notBundledImportNames"] = [{"name": "unknown.dll"}]
            with self.assertRaises(ValueError):
                audit.review_original(18, Path("unused"), {})
            good["notBundledImportNames"] = [
                {"name": n} for n in audit.EXPECTED_EXTERNAL]
            good["staticReachableMissingNamedNoticeConsumers"] = []
            with self.assertRaises(ValueError):
                audit.review_original(18, Path("unused"), {})


if __name__ == "__main__":
    unittest.main()
