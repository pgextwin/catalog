"""Fail-closed external direct-provider Publisher policy hostile inputs."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from external_formal_publisher_policy import POLICY, inspect_policy  # noqa: E402
from external_direct_link_review import strict_read  # noqa: E402


class ExternalFormalPublisherPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = strict_read(ROOT / POLICY)

    def test_only_two_reviewed_origins_are_nonpublishing(self):
        receipt = inspect_policy(ROOT)
        self.assertEqual("EXTERNAL_GITHUB_RELEASE_ASSET", receipt["sourceKind"])
        self.assertEqual("external-direct-provider-publisher",
                         receipt["publisherEnvironment"])
        self.assertEqual(64, len(receipt["policySha256"]))
        self.assertEqual("EXTERNAL_APP_KEY_SCOPE_VERIFIED_PUBLISH_DENY", receipt["status"])
        for key in ("formalAdmissionReady", "sourcePublisherAuthorized",
                    "downloadAuthorized", "mirrorAuthorized"):
            self.assertIs(receipt[key], False)

    def test_inherited_native_environment_or_app_cannot_authorize(self):
        cases = {
            "mode": "ENFORCE",
            "publisherEnvironment": "publisher",
            "publisherAppId": 5451798,
            "publisherInstallationId": 174720074,
            "publisherEnvironmentId": 1,
            "protectedEnvironmentVerified": False,
            "leastPrivilegeAppVerified": False,
            "originalMainIndependentSigstoreVerified": True,
            "formalSourceSpecificAuthorization": True,
            "approvedOperation": "DIRECT_DOWNLOAD",
            "mirrorAuthorized": True,
            "redistributionAuthorized": True,
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                doc = copy.deepcopy(self.policy)
                doc[field] = value
                with self.assertRaises(ValueError):
                    inspect_policy(ROOT, doc)

    def test_source_substitution_and_permission_escalation_denied(self):
        for field, value in (
            ("sourceRepo", "pgextwin/catalog"), ("releaseId", 1),
            ("assetId", 2), ("noticeRequirement", "NOT_NEEDED"),
            ("dependencyTreatment", "REDISTRIBUTE_CLIENT"),
            ("referenceReviewOnly", False),
            ("sourcePublisherAuthorized", True), ("downloadAuthorized", True),
            ("mirrorAuthorized", True)
        ):
            with self.subTest(field=field):
                doc = copy.deepcopy(self.policy)
                doc["records"][0][field] = value
                with self.assertRaises(ValueError):
                    inspect_policy(ROOT, doc)

    def test_unknown_missing_or_duplicate_source_denied(self):
        for edit in ("unknown", "missing", "duplicate", "third", "empty"):
            with self.subTest(edit=edit):
                doc = copy.deepcopy(self.policy)
                if edit == "unknown":
                    doc["signedByNativePublisher"] = True
                elif edit == "missing":
                    del doc["publisherEnvironment"]
                elif edit == "duplicate":
                    doc["records"][1] = copy.deepcopy(doc["records"][0])
                elif edit == "third":
                    doc["records"].append(copy.deepcopy(doc["records"][0]))
                else:
                    doc["records"] = []
                with self.assertRaises(ValueError):
                    inspect_policy(ROOT, doc)

    def test_boolean_vs_integer_and_null_type_confusion_denied(self):
        for field, value in (
            ("protectedEnvironmentVerified", 0),
            ("leastPrivilegeAppVerified", 0),
            ("publisherAppId", False),
            ("publisherInstallationId", ""),
            ("publisherEnvironmentId", None),
            ("publisherAppProof", []),
            ("formalSourceSpecificAuthorization", None),
        ):
            with self.subTest(field=field):
                doc = copy.deepcopy(self.policy)
                doc[field] = value
                with self.assertRaises(ValueError):
                    inspect_policy(ROOT, doc)


    def test_exact_genuine_app_proof_pointer_cannot_be_substituted(self):
        for field, value in (
            ("repository", "pgextwin/catalog"),
            ("workflow", "publisher-app-proof.yml"),
            ("runId", 1),
            ("runAttempt", 2),
            ("sourceCommit", "0" * 40),
            ("conclusion", "skipped"),
            ("operation", "CREATE_RELEASE"),
        ):
            with self.subTest(field=field):
                doc = copy.deepcopy(self.policy)
                doc["publisherAppProof"][field] = value
                with self.assertRaises(ValueError):
                    inspect_policy(ROOT, doc)

    def test_administrative_proof_is_not_source_specific_admission(self):
        receipt = inspect_policy(ROOT)
        self.assertEqual(41817355221, receipt["appProofRunId"])
        self.assertFalse(receipt["formalAdmissionReady"])
        for key in ("sourcePublisherAuthorized", "downloadAuthorized", "mirrorAuthorized"):
            self.assertFalse(receipt[key])
        self.assertFalse(self.policy["formalSourceSpecificAuthorization"])
        self.assertFalse(self.policy["originalMainIndependentSigstoreVerified"])
        self.assertEqual("NONE", self.policy["approvedOperation"])

if __name__ == "__main__":
    unittest.main()
