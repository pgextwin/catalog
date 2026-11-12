"""Offline hostile tests; no source-index GET, ZIP download, admission or publish."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from issue112_cybertec_windows_index import BASE, collect, parse_index
from issue112_cybertec_latest_review import label_rank, review


def listing(*names):
    return ("<a href='../'>../</a>" + "".join(
        f"<a href='{x}'>{x}</a>" for x in names)).encode()


def receipts():
    return collect({
        "16": parse_index(listing(
            "pg_partman-16-public-v5.4.2-1.zip",
            "pg_partman-16-public-v5.4.3-1.zip",
            "orafce-16-public-VERSION_4_16_5-1.zip",
            "pg_squeeze-16-public-REL1_9_1-1.zip"), "16"),
        "17": parse_index(listing(
            "pg_partman-17-public-v5.4.3-1.zip",
            "pg_hint_plan-17-17-public-REL17_1_7_1-5-gd06add-1.zip"), "17"),
    })


class CybertecReviewTests(unittest.TestCase):
    def test_latest_numeric_scopes_each_extension_and_pg(self):
        result = review(receipts(), latest_only=True)
        self.assertEqual(len(result["candidates"]), 5)
        self.assertEqual({(x["pgMajor"], x["providerBuildLabelUntrusted"])
                          for x in result["candidates"] if x["extension"] == "pg_partman"},
                         {("16", "v5.4.3-1"), ("17", "v5.4.3-1")})
        self.assertEqual(result["selection"], "MAX_NUMERIC_PROVIDER_LABEL_PER_EXTENSION_PG")
        for flag in ("publicGetAuthorized", "mirrorAuthorized", "publisherAuthorized",
                     "releaseAuthorized", "latestUpstreamVersionVerified",
                     "communityPostgresqlAbiVerified", "independentSignedAdmission"):
            self.assertIs(result[flag], False)

    def test_exact_provider_label_is_not_upstream_version(self):
        result = review(receipts(), extension="pg_partman", label="v5.4.2-1")
        self.assertEqual([(x["pgMajor"], x["fileName"]) for x in result["candidates"]],
                         [("16", "pg_partman-16-public-v5.4.2-1.zip")])
        self.assertEqual(result["requestedPackagingLabel"], "v5.4.2-1")
        self.assertEqual(len(review(receipts(), extension="pg_partman",
                                    label="v9.9.9")["candidates"]), 0)
        with self.assertRaises(ValueError):
            review(receipts(), label="v5.4.3-1")

    def test_compares_versions_numerically_and_drops_redundant_pg_prefix(self):
        self.assertGreater(label_rank("v5.4.10-1", "17"), label_rank("v5.4.9-1", "17"))
        self.assertEqual(label_rank("REL17_1_7_1-5-gd06add-1", "17"), (1, 7, 1, 0))
        self.assertEqual(label_rank("VERSION_4_16_5-1", "16"), (4, 16, 5, 0))
        self.assertEqual(label_rank("REL1_9_1-1", "16"), (1, 9, 1, 0))
        self.assertIsNone(label_rank("unversioned-preview", "16"))

    def test_unrankable_group_never_claims_latest(self):
        x = receipts()
        row = next(item for item in x["candidates"] if item["extension"] == "orafce")
        row["providerBuildLabelUntrusted"] = "unversioned-preview"
        row["fileName"] = "orafce-16-public-unversioned-preview.zip"
        row["originalUrlUntrusted"] = BASE + "16/extension/" + row["fileName"]
        result = review(x, latest_only=True)
        self.assertEqual(result["unrankableGroups"], [
            {"extension": "orafce", "pgMajor": "16", "reason": "UNRANKABLE_PROVIDER_LABEL"}])
        self.assertFalse(any(y["extension"] == "orafce" for y in result["candidates"]))

    def test_unselected_candidate_poison_does_not_get_hidden(self):
        x = receipts()
        x["candidates"][0]["publicGetAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "drift"):
            review(x, extension="pg_hint_plan", latest_only=True)
        x = receipts()
        x["candidates"][0]["originalUrlUntrusted"] = "https://evil.test/a.zip"
        with self.assertRaisesRegex(ValueError, "drift"):
            review(x, extension="pg_hint_plan")

    def test_malformed_identity_and_duplicate_denied(self):
        x = receipts()
        x["candidates"][0]["fileName"] = "pg_partman-18-public-v5.4.2-1.zip"
        with self.assertRaises(ValueError):
            review(x)
        x = receipts()
        x["candidates"].append(dict(x["candidates"][0]))
        x["zipCandidates"] += 1
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            review(x)

    def test_root_authorization_and_unknown_input_denied(self):
        x = receipts()
        x["releaseAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "trust escalation"):
            review(x)
        with self.assertRaises(ValueError):
            review(receipts(), extension="../../evil")
        with self.assertRaises(ValueError):
            review(receipts(), extension="orafce", label="4.1/unsafe")


if __name__ == "__main__":
    unittest.main()
