#!/usr/bin/env python3
"""R09-01 native Catalog shadow contract; PR-only, no signed feed Release."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SHADOW=ROOT/"metadata/issue311-r09-shadow-nonpublishing.json"
class PrivatePreview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e=json.loads(SHADOW.read_text("utf8"))
        cls.index=json.loads((ROOT/"index.json").read_text("utf8"))
        cls.record=json.loads((ROOT/"extensions/orafce.json").read_text("utf8"))
        cls.majors=json.loads((ROOT/"config/cli-feed-majors.json").read_text("utf8"))
    def test_exact_immutable_source(self):
        e=self.e;s=e["source"]
        self.assertEqual(e["schemaVersion"],1)
        self.assertEqual(e["type"],"pgextwin-nonpublishing-catalog-shadow")
        self.assertEqual(e["status"],"BLOCKED_PREPARE_NOT_A_RELEASE")
        self.assertEqual(e["decision"],"PUBLISH_DENY")
        self.assertEqual(e["catalogBaseSha"],"dc8390fd816aa7bf0bf3b541e822b1320a47846e")
        self.assertEqual(e["websiteBaseSha"],"2eb3bd618f230cea424b99dac5148ca72d923cd7")
        self.assertEqual(s["sourceKind"],"APP_BOT_PREPARE_WORKFLOW_DISPATCH_SIGNED_BUILD_ONLY")
        self.assertEqual(s["requestRawSha256"],"174b48df34a82ef147b599b1b33a86964990ea6ee4fb6932b365e338dd23410f")
        self.assertEqual(s["stateGitBlobSha"],"e588b93f5f607dc05e240e07c3351d75e1f34727")
        self.assertEqual([s["centralRunId"],s["fleetRunId"],s["signedLocalRunId"],s["r09ReadOnlyRunId"]],[41073991273,41074138918,41074341848,41082159167])
        self.assertEqual(s["r09ArtifactId"],12989134273)
        self.assertEqual(s["r09ArtifactActualZipSha256"],"a6a9e5a02d45eb4dd71419726c8e1a55c701b9e4befa6935e7e3d7e8db698cb6")
    def test_existing_public_catalog_unchanged(self):
        self.assertEqual(self.index["schemaVersion"],2)
        self.assertEqual(self.index["extensions"],sorted(self.index["extensions"]))
        self.assertEqual(len(self.index["extensions"]),17)
        self.assertIn("orafce",self.index["extensions"])
        self.assertEqual(self.record["latest"]["releaseTag"],self.e["historicalPublicReleaseTag"])
        self.assertEqual(self.record["latest"]["publishedAt"],"2026-10-10T15:49:07Z")
        self.assertEqual(self.majors["postgresqlMajors"],self.e["pgMajors"])
        self.assertEqual(set(self.record["postgresql"]),set(self.e["pgMajors"]))
    def test_deny_all_publication(self):
        for key in ("publicReleaseAuthorized","proposedPublicRecord","writeOutcomeUnknown",
            "catalogMainUpdateAuthorized","createPublicCatalogRecord","createTagOrRelease",
            "generatePublicSignedFeed","runWebsitePublish","publisherTokenRequested"):
            self.assertIs(self.e[key],False,key)
        self.assertEqual(self.e["extension"],"orafce")
        proof=self.e["safeFeedGateProof"]
        self.assertEqual(proof["protectedCatalogMainSha"],"8e1fca2987293768fc7d408513f95ec007a804b7")
        self.assertEqual(proof["safetyPr"],180)
        self.assertEqual(proof["originalValidateRunId"],41135419066)
        self.assertEqual(proof["originalFeedWorkflowRunId"],41135512679)
        self.assertEqual(proof["originalGateJobId"],124336856340)
        for key in ("gateConclusion","feedRunConclusion"):
            self.assertEqual(proof[key],"success")
        for key in ("attestConclusion","publishMetadataOnlyConclusion"):
            self.assertEqual(proof[key],"skipped")
        self.assertEqual(proof["logMarker"],"CATALOG_FEED_NOOP_NO_PUBLIC_RECORD_CHANGE")
        self.assertEqual(proof["decision"],"PUBLISH_DENY")
        self.assertIn("no Catalog record or Website public write",self.e["next"])
    def test_existing_cli_feed_sources_present(self):
        self.assertIn("def build_feed(",(ROOT/"scripts/cli_signed_feed.py").read_text("utf8"))
        self.assertTrue((ROOT/"dotnet/src/PgExtWin.Cli/Program.cs").is_file())
        self.assertTrue((ROOT/"dotnet/src/PgExtWin.Releases/SignedPublicCatalogFeed.cs").is_file())
        self.assertTrue((ROOT/"tests/test_cli_signed_feed.py").is_file())
if __name__=="__main__":
    unittest.main()
