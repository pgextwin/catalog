"""Hostile offline regression: names/docs must never imply a signed GET grant."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgroonga_rights_join as join


def receipt(paths, docs):
    return {
        "pgMajor": 18, "version": "4.1.0", "expectedZipSha256": "a" * 64,
        "binaryMemberReceipts": [
            {"path": path, "bytes": 5, "sha256": str(i).zfill(64)}
            for i, path in enumerate(paths)
        ],
        "licenseNoticeFiles": [
            {"path": path, "sha256": str(i + 100).zfill(64)}
            for i, path in enumerate(docs)
        ],
    }


class RightsJoinTests(unittest.TestCase):
    def test_group_manifest_is_exhaustive_and_nonambiguous(self):
        self.assertEqual(len(join.PATH_TO_GROUP), 43)
        self.assertEqual(sum(map(len, join.PATH_GROUPS.values())), 43)
        self.assertEqual(len(join.DOC_CANDIDATES["xxhash"]), 0)

    def test_each_observed_binary_retains_hash_and_never_authorizes(self):
        paths = sorted(join.PATH_TO_GROUP)
        docs = sorted({d for group in join.DOC_CANDIDATES.values() for d in group})
        docs.append(join.MRUBY_LEGAL_PATH)
        docs += [f"share/other/{i}/LICENSE" for i in range(25 - len(docs))]
        evidence = join.join_receipts(receipt(paths, docs), strict=True)
        self.assertEqual(evidence["binaryCount"], 43)
        self.assertEqual(evidence["documentCount"], 25)
        self.assertEqual(evidence["pathIdentityCoverage"], 43)
        for original, mapped in zip(sorted(receipt(paths, docs)["binaryMemberReceipts"], key=lambda x:x["path"]), evidence["binaryRightsReviewRows"]):
            self.assertEqual(original["sha256"], mapped["sha256"])
            for flag in ("exactComponentVersionVerified", "componentLicenseNoticeVerified",
                         "sourceToBinaryProvenanceVerified", "candidateAssociationIsLegalAcceptance"):
                self.assertIs(mapped[flag], False)
        for flag in ("allComponentVersionsVerified", "perBinaryLegalAcceptanceComplete",
                     "sourceToBinaryProvenanceVerified", "independentSignedGetAdmission",
                     "publicGetAuthorized", "mirrorAuthorized", "publisherAuthorized"):
            self.assertIs(evidence[flag], False)
        self.assertEqual(evidence["binaryWithoutNamedDocumentCandidateCount"], 2)
        self.assertEqual(len(evidence["documentsNotLinkedByBinaryNameTriage"]), 13)

    def test_matching_count_cannot_replace_mruby_legal_with_unrelated_document(self):
        paths = sorted(join.PATH_TO_GROUP)
        docs = [f"share/other/{i}/LICENSE" for i in range(25)]
        with self.assertRaises(ValueError):
            join.join_receipts(receipt(paths, docs), strict=True)

    def test_mecab_copying_alone_does_not_supply_referenced_license_bodies(self):
        x = join.join_receipts(receipt(["bin/libmecab.dll"],
                                      ["share/groonga/mecab/COPYING"]))
        row = x["binaryRightsReviewRows"][0]
        self.assertEqual(set(row["missingExpectedCandidateDocuments"]),
                         {"share/groonga/mecab/BSD", "share/groonga/mecab/GPL",
                          "share/groonga/mecab/LGPL"})
        self.assertFalse(row["componentLicenseNoticeVerified"])

    def test_xxhash_has_no_fabricated_license_document(self):
        x = join.join_receipts(receipt(["bin/libxxhash.dll", "bin/xxhsum.exe"],
                                       ["share/groonga/COPYING"]))
        self.assertEqual(x["binaryWithoutNamedDocumentCandidateCount"], 2)
        self.assertTrue(all(not row["candidateDocuments"] for row in x["binaryRightsReviewRows"]))

    def test_missing_named_doc_is_missing_not_assumed(self):
        x = join.join_receipts(receipt(["bin/msgpack-c.dll"],
                                       ["share/groonga/msgpack-c/COPYING"]))
        row = x["binaryRightsReviewRows"][0]
        self.assertEqual(len(row["candidateDocuments"]), 1)
        self.assertEqual(len(row["missingExpectedCandidateDocuments"]), 2)
        self.assertFalse(row["componentLicenseNoticeVerified"])

    def test_similar_path_never_inherits_component_license(self):
        x = join.join_receipts(receipt(["bin/libxxhash.dll.bak"],
                                       ["share/groonga/COPYING"]))
        self.assertIsNone(x["binaryRightsReviewRows"][0]["candidateComponentGroup"])
        self.assertEqual(x["pathIdentityCoverage"], 0)
        with self.assertRaises(ValueError):
            join.join_receipts(receipt(["bin/libxxhash.dll.bak"], []), strict=True)

    def test_duplicate_paths_fail(self):
        with self.assertRaises(ValueError):
            join.join_receipts(receipt(["bin/libxxhash.dll"] * 2, []))
        with self.assertRaises(ValueError):
            join.join_receipts(receipt(["bin/libxxhash.dll"], ["same/LICENSE"] * 2))

    def test_incomplete_or_extra_original_fails_strict_admission(self):
        all_paths = sorted(join.PATH_TO_GROUP)
        for paths in (all_paths[:-1], all_paths + ["bin/unknown.dll"]):
            with self.assertRaises(ValueError):
                join.join_receipts(receipt(paths, []), strict=True)


    def test_exact_official_release_jobs_provide_separate_xxhash_083_build_hints(self):
        self.assertEqual(set(join.UPSTREAM_WINDOWS_JOBS), {14, 15, 16, 17, 18})
        self.assertEqual(len(set(join.UPSTREAM_WINDOWS_JOBS.values())), 5)
        for pg, job in sorted(join.UPSTREAM_WINDOWS_JOBS.items()):
            for binary in ("bin/libxxhash.dll", "bin/xxhsum.exe"):
                original = receipt([binary], ["share/groonga/COPYING"])
                original["pgMajor"] = pg
                row = join.join_receipts(original)["binaryRightsReviewRows"][0]
                hint = row["officialProducerBuildVersionHint"]
                self.assertEqual(hint["observedMesonVersion"], "0.8.3")
                self.assertIn(f"/job/{job}", hint["producerJobUrl"])
                self.assertIn(join.UPSTREAM_BUILD_COMMIT, hint["officialTaggedMesonWrapUrl"])
                self.assertTrue(hint["originalLogLinksAndInstallsBothXxHashBinaries"])
                self.assertIn("Cyan4973/xxHash/blob/v0.8.3/LICENSE",
                              hint["originalAuthorLicenseCandidateUrl"])
                self.assertEqual(row["candidateDocuments"], [])
                for key in ("licenseFilePresentInOriginalTwentyNamedNotices",
                            "originalReleaseBinaryToProducerAttestationVerified",
                            "licenseNoticeComplete", "publicGetAuthorized"):
                    self.assertIs(hint[key], False)
                self.assertIs(row["exactComponentVersionVerified"], False)
                self.assertIs(row["componentLicenseNoticeVerified"], False)

    def test_unknown_and_spoofed_source_never_inherit_xxhash_receipt(self):
        x = receipt(["bin/libxxhash.dll.bak", "bin/xxhsum.exe.tmp"], [])
        result = join.join_receipts(x)
        self.assertTrue(all(row["officialProducerBuildVersionHint"] is None
                            for row in result["binaryRightsReviewRows"]))
        x = receipt(["bin/libxxhash.dll"], [])
        x["pgMajor"] = 19
        row = join.join_receipts(x)["binaryRightsReviewRows"][0]
        self.assertIsNone(row["officialProducerBuildVersionHint"])
        self.assertFalse(join.join_receipts(x)["publicGetAuthorized"])

    def test_other_41_binaries_not_attributed_to_xxhash_source(self):
        paths = [p for p in join.PATH_TO_GROUP if join.PATH_TO_GROUP[p] != "xxhash"]
        x = join.join_receipts(receipt(paths, []))
        self.assertEqual(len(paths), 41)
        self.assertTrue(all(row["officialProducerBuildVersionHint"] is None
                            for row in x["binaryRightsReviewRows"]))


if __name__ == "__main__":
    unittest.main()
