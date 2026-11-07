"""Source-specific direct GET admission REQUEST: hostile tests, never authorizing."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from external_direct_get_intake import (  # noqa: E402
    INTAKE, inspect_intake, validate_intake,
)
from external_direct_link_review import strict_read  # noqa: E402


class DirectGetIntakeTests(unittest.TestCase):
    def setUp(self):
        self.data = strict_read(ROOT / INTAKE)
        self.row = self.data["records"][0]

    @staticmethod
    def snapshot(row):
        return {
            row["sourceRepo"]: {
                "repository": {
                    "full_name": row["sourceRepo"],
                    "id": row["repositoryId"],
                    "html_url": "https://github.com/" + row["sourceRepo"],
                },
                "release": {
                    "id": row["releaseId"],
                    "tag_name": row["releaseTag"],
                    "draft": False,
                    "prerelease": False,
                    "html_url": ("https://github.com/" + row["sourceRepo"] +
                                 "/releases/tag/" + row["releaseTag"]),
                    "assets": [{
                        "id": row["assetId"],
                        "name": row["assetName"],
                        "size": row["originalBytes"],
                        "digest": "sha256:" + row["originalSha256"],
                        "state": "uploaded",
                        "browser_download_url": row["originalProviderUrl"],
                    }],
                },
            },
        }

    def test_pg_trickle_candidate_readonly_not_an_approval(self):
        rows = validate_intake(self.data)
        self.assertEqual(1, len(rows))
        self.assertEqual("trickle-labs/pg-trickle", rows[0]["sourceRepo"])
        result = inspect_intake()
        self.assertEqual("CANDIDATE_ONLY_PUBLISH_DENY", result["state"])
        self.assertEqual("ORIGINAL_PROVIDER_GET_ONLY", result["intendedOperation"])
        self.assertEqual(64, len(result["intakeSha256"]))
        self.assertEqual(0, result["metadataMatchesWithoutAuthenticatingSnapshots"])
        self.assertEqual("NONE", result["approvalIssuer"])
        for flag in ("independentSigstoreAuthorizedPin", "downloadAuthorized",
                     "mirrorAuthorized", "redistributionAuthorized"):
            self.assertIs(result[flag], False)

    def test_synthetic_metadata_match_still_denies(self):
        res = inspect_intake(ROOT, self.data, self.snapshot(self.row))
        self.assertEqual(1, res["metadataMatchesWithoutAuthenticatingSnapshots"])
        self.assertIs(res["downloadAuthorized"], False)
        self.assertIs(res["independentSigstoreAuthorizedPin"], False)
        self.assertEqual("NONE", res["approvalIssuer"])

    def test_root_mutations_rejected(self):
        changes = {
            "sourceKind": "NATIVE_PGEXTWIN_RELEASE",
            "intendedOperation": "MIRROR_ORIGINAL",
            "reviewStatus": "SIGNED_NONPUBLISHING",
            "authorizationIssuer": "ShutenOishi",
            "independentSignedAdmission": True,
            "publicationAuthorized": True,
            "downloadAuthorized": True,
            "mirrorAuthorized": True,
            "redistributionAuthorized": True,
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                doc = copy.deepcopy(self.data)
                doc[key] = value
                with self.assertRaises(ValueError):
                    validate_intake(doc)

    def test_source_substitutions_and_shape_denied(self):
        changes = {
            "sourceRepo": "pgextwin/catalog",
            "repositoryId": True,
            "releaseId": 0,
            "assetId": False,
            "originalBytes": 64 * 1024 * 1024 + 1,
            "pgMajor": "19",
            "targetEnvironment": "Linux x64",
            "originalSha256": "0" * 64,
            "originalProviderUrl": "https://example.com/original.zip",
            "assetName": "../evil.zip",
            "releaseTag": "../main",
            "licenseUrl": "http://github.com/trickle-labs/pg-trickle/LICENSE",
            "licenseSpdx": "",
            "noticeTreatment": "OK",
            "dependencyTreatment": "OK",
            "downloadAuthorized": True,
            "mirrorAuthorized": True,
            "sourcePublisherAuthorized": True,
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                doc = copy.deepcopy(self.data)
                doc["records"][0][key] = value
                # The hash-only mutation still has a valid length; with a
                # supplied authenticated-snapshot shape it must fail closed.
                if key == "originalSha256":
                    with self.assertRaises(ValueError):
                        inspect_intake(ROOT, doc, self.snapshot(self.row))
                else:
                    with self.assertRaises(ValueError):
                        validate_intake(doc)

    def test_held_initial_sources_not_eligible(self):
        doc = copy.deepcopy(self.data)
        row = doc["records"][0]
        row["sourceRepo"] = "laurenz/oracle_fdw"
        row["releaseId"] = 335861225
        row["assetId"] = 442625860
        row["originalProviderUrl"] = ("https://github.com/laurenz/oracle_fdw/releases/download/" +
                                      row["releaseTag"] + "/" + row["assetName"])
        with self.assertRaisesRegex(ValueError, "held initial"):
            validate_intake(doc)

    def test_duplicate_extra_missing_and_numeric_confusion_denied(self):
        for mode in ("duplicate", "extra", "missing", "wronglist", "badinteger"):
            with self.subTest(mode=mode):
                doc = copy.deepcopy(self.data)
                if mode == "duplicate":
                    doc["records"].append(copy.deepcopy(doc["records"][0]))
                if mode == "extra":
                    doc["signedByNativePublisher"] = True
                if mode == "missing":
                    del doc["records"][0]["runtimeEvidence"]
                if mode == "wronglist":
                    doc["records"] = {}
                if mode == "badinteger":
                    doc["records"][0]["runtimeEvidence"]["runAttempt"] = True
                with self.assertRaises(ValueError):
                    validate_intake(doc)

    def test_untrusted_api_substitution_denied(self):
        for field, value in (
            ("full_name", "other/pg-trickle"),
            ("id", 99999),
        ):
            with self.subTest(field=field):
                snap = self.snapshot(self.row)
                snap[self.row["sourceRepo"]]["repository"][field] = value
                with self.assertRaises(ValueError):
                    inspect_intake(ROOT, self.data, snap)
        for field, value in (
            ("id", 1), ("tag_name", "evil"), ("draft", True),
            ("prerelease", True),
        ):
            with self.subTest(field=field):
                snap = self.snapshot(self.row)
                snap[self.row["sourceRepo"]]["release"][field] = value
                with self.assertRaises(ValueError):
                    inspect_intake(ROOT, self.data, snap)
        for field, value in (
            ("id", 777), ("size", 1), ("name", "evil.zip"),
            ("digest", "sha256:" + "0" * 64),
            ("browser_download_url", "https://evil.example/file.zip"),
        ):
            with self.subTest(field=field):
                snap = self.snapshot(self.row)
                snap[self.row["sourceRepo"]]["release"]["assets"][0][field] = value
                with self.assertRaises(ValueError):
                    inspect_intake(ROOT, self.data, snap)

    def test_source_run_is_not_a_local_permission(self):
        for key, value in (
            ("repository", "pgextwin/build"),
            ("runId", False),
            ("runAttempt", 2),
            ("event", "workflow_dispatch"),
            ("headSha", "nope"),
            ("conclusion", "skipped"),
            ("scope", "SYNTHETIC TEST"),
        ):
            with self.subTest(key=key):
                doc = copy.deepcopy(self.data)
                doc["records"][0]["runtimeEvidence"][key] = value
                with self.assertRaises(ValueError):
                    validate_intake(doc)

    def test_duplicate_json_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.json"
            p.write_text('{"downloadAuthorized":false,"downloadAuthorized":true}')
            with self.assertRaises(ValueError):
                strict_read(p)


if __name__ == "__main__":
    unittest.main()
