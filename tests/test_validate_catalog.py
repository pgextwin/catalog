import copy
import hashlib
import json
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_catalog.py"

spec = importlib.util.spec_from_file_location("validate_catalog", MODULE_PATH)
validate_catalog = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validate_catalog
spec.loader.exec_module(validate_catalog)


class CatalogV2ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = validate_catalog.load_json(
            ROOT / "schema" / "extension.schema.json"
        )
        cls.valid = validate_catalog.load_json(
            ROOT / "extensions" / "pg_cron.json"
        )

    def errors_for(self, record):
        errors = validate_catalog.schema_errors(
            self.schema, record, "fixture"
        )
        errors.extend(
            validate_catalog.validate_record_semantics(record["name"], record)
        )
        return errors

    def assert_has_error(self, record, needle):
        errors = self.errors_for(record)
        self.assertTrue(
            any(needle in error for error in errors),
            f"expected error containing {needle!r}; got:\n" + "\n".join(errors),
        )


    def test_public_release_gateway_fallback_gets_anonymous_real_bytes(self):
        # All requests in this test are mocked; the PR's --verify-remote job
        # supplies the separate genuine networked byte-read acceptance.
        repository, tag = "pgextwin/hypopg", "v1.4.1-windows.1"
        data = b"1" * 64 + b"  example.zip\n"
        asset = {
            "name": "SHA256SUMS.txt",
            "id": 123456,
            "size": len(data),
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "browser_download_url":
                f"https://github.com/{repository}/releases/download/{tag}/SHA256SUMS.txt",
        }
        api_url = f"https://api.github.com/repos/{repository}/releases/assets/123456"
        calls = []

        def get(url, *, token=None, accept="application/vnd.github+json"):
            calls.append((url, token, accept))
            if url == asset["browser_download_url"]:
                raise RuntimeError("remote request failed after 3 attempts: HTTP Error 504: Gateway Time-out")
            self.assertEqual(url, api_url)
            return data, {"Content-Type": "application/octet-stream"}

        with patch.object(validate_catalog, "http_get", side_effect=get):
            parsed = validate_catalog.read_public_release_checksums(repository, tag, asset)
        self.assertEqual(parsed, {"example.zip": "1" * 64})
        self.assertEqual(calls, [
            (asset["browser_download_url"], None, "text/plain"),
            (api_url, None, "application/octet-stream"),
        ])

    def test_public_release_fallback_rejects_rest_json_even_if_metadata_hash_matches(self):
        repo, tag = "pgextwin/hypopg", "v1.4.1-windows.1"
        data = b'{"name":"SHA256SUMS.txt"}'
        asset = {
            "name": "SHA256SUMS.txt", "id": 123456, "size": len(data),
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "browser_download_url": f"https://github.com/{repo}/releases/download/{tag}/SHA256SUMS.txt",
        }
        with patch.object(validate_catalog, "http_get", side_effect=[
            RuntimeError("HTTP Error 504: Gateway Time-out"),
            (data, {"Content-Type": "application/json"}),
        ]) as mock_get:
            with self.assertRaisesRegex(ValueError, "JSON metadata"):
                validate_catalog.read_public_release_checksums(repo, tag, asset)
        self.assertEqual(mock_get.call_count, 2)

    def test_public_release_fallback_never_hides_404(self):
        repo, tag = "pgextwin/hypopg", "v1.4.1-windows.1"
        asset = {
            "name": "SHA256SUMS.txt", "id": 123456, "size": 77,
            "digest": None,
            "browser_download_url": f"https://github.com/{repo}/releases/download/{tag}/SHA256SUMS.txt",
        }
        with patch.object(validate_catalog, "http_get", side_effect=RuntimeError("HTTP Error 404: Not Found")) as mock_get:
            with self.assertRaisesRegex(RuntimeError, "HTTP Error 404"):
                validate_catalog.read_public_release_checksums(repo, tag, asset)
        mock_get.assert_called_once()

    def test_public_release_fallback_rejects_corrupt_primary_without_alternate(self):
        repo, tag = "pgextwin/hypopg", "v1.4.1-windows.1"
        data = b"1" * 64 + b"  example.zip\n"
        asset = {
            "name": "SHA256SUMS.txt", "id": 123456, "size": len(data),
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "browser_download_url": f"https://github.com/{repo}/releases/download/{tag}/SHA256SUMS.txt",
        }
        with patch.object(validate_catalog, "http_get", return_value=(b"2" * len(data), {})) as mock_get:
            with self.assertRaisesRegex(ValueError, "SHA256 differs"):
                validate_catalog.read_public_release_checksums(repo, tag, asset)
        mock_get.assert_called_once()

    def test_public_release_fallback_rejects_wrong_byte_length(self):
        repo, tag = "pgextwin/hypopg", "v1.4.1-windows.1"
        asset = {
            "name": "SHA256SUMS.txt", "id": 123456, "size": 99,
            "digest": None,
            "browser_download_url": f"https://github.com/{repo}/releases/download/{tag}/SHA256SUMS.txt",
        }
        with patch.object(validate_catalog, "http_get", side_effect=[
            RuntimeError("HTTP Error 503: Service Unavailable"),
            (b"short", {"Content-Type": "application/octet-stream"}),
        ]):
            with self.assertRaisesRegex(ValueError, "byte length differs"):
                validate_catalog.read_public_release_checksums(repo, tag, asset)

    def test_remote_check_uses_stored_authorized_tag_not_unverified_newest_tag(self):
        """Keep a verified older Catalog entry while a newer Publisher run is DENIED."""
        record = validate_catalog.load_json(ROOT / "extensions" / "hypopg.json")
        latest = record["latest"]
        tagged_url = (
            "https://api.github.com/repos/pgextwin/hypopg/releases/tags/"
            + latest["releaseTag"]
        )
        response = {
            "tag_name": latest["releaseTag"],
            "draft": False,
            "prerelease": False,
            "published_at": latest["publishedAt"],
            "html_url": latest["releaseUrl"],
            "assets": [],
        }
        with patch.object(
            validate_catalog, "http_get",
            return_value=(json.dumps(response).encode("utf-8"), {}),
        ) as get:
            errors = validate_catalog.verify_release(record, "synthetic-read-token")
        get.assert_called_once_with(tagged_url, token="synthetic-read-token")
        # The deliberately incomplete fixture is still REJECTED on checksums.
        # This demonstrates pinned-tag lookup only; it is NOT publication proof.
        self.assertEqual(
            errors,
            ["release is missing checksums asset 'SHA256SUMS.txt'"],
        )

    def test_remote_tagged_release_rejects_identity_and_publication_attacks(self):
        record = validate_catalog.load_json(ROOT / "extensions" / "hypopg.json")
        tag = record["latest"]["releaseTag"]
        good = {
            "tag_name": tag,
            "draft": False,
            "prerelease": False,
            "published_at": record["latest"]["publishedAt"],
            "html_url": record["latest"]["releaseUrl"],
            "assets": [],
        }
        for mutate in (
            lambda r: r.update(tag_name=tag + "-forged"),
            lambda r: r.update(draft=True),
            lambda r: r.update(prerelease=True),
        ):
            with self.subTest(mutate=mutate):
                response = copy.deepcopy(good)
                mutate(response)
                with patch.object(
                    validate_catalog, "http_get",
                    return_value=(json.dumps(response).encode("utf-8"), {}),
                ):
                    errors = validate_catalog.verify_release(record, None)
                self.assertTrue(errors)
                self.assertNotIn("release is missing checksums asset", errors[0])
        unsafe = copy.deepcopy(record)
        unsafe["latest"]["releaseTag"] = "../latest"
        with patch.object(validate_catalog, "http_get") as get:
            self.assertEqual(
                validate_catalog.verify_release(unsafe, None),
                ["unsafe Catalog-pinned Release tag"],
            )
        get.assert_not_called()

    def test_step18_plpgsql_check_release_metadata(self):
        record = validate_catalog.load_json(ROOT / "extensions" / "plpgsql_check.json")
        self.assertEqual([], self.errors_for(record))
        self.assertTrue({"15", "16", "17", "18"}.issubset({major for major, metadata in record["postgresql"].items() if metadata["available"]}))
        if "14" in record["postgresql"]:
            self.assertNotEqual("v2.10.13-windows.1", record["latest"]["releaseTag"])
        self.assertNotIn("19", record["postgresql"])
        self.assertEqual("optional", record["runtime"]["requirements"]["preload"])
        self.assertEqual("required", record["runtime"]["requirements"]["extensionCreation"])
        self.assertFalse(record["runtime"]["requirements"]["backgroundWorker"])
        self.assertEqual("not-covered", record["capabilities"]["coverage"]["upgrade"])
        self.assertEqual(["detect-invalid-record-field"], [s["id"] for s in record["capabilities"]["functionalScenarios"]])
        self.assertEqual(40, len(record["capabilitiesSource"]["commit"]))
        self.assertTrue(all(metadata["evidence"]["buildProvenanceAttestation"]["available"] and metadata["evidence"]["sbomAttestation"]["available"] for metadata in record["postgresql"].values()))


    def test_pg_partman_release_describes_optional_bundled_bgw(self):
        record = validate_catalog.load_json(
            ROOT / "extensions" / "pg_partman.json"
        )
        self.assertEqual([], self.errors_for(record))
        self.assertIn("BGW DLL included", record["description"])
        self.assertNotIn("BGW excluded", record["description"])
        self.assertTrue(record["runtime"]["requirements"]["backgroundWorker"])
        self.assertEqual("optional", record["runtime"]["requirements"]["preload"])
        self.assertEqual("covered", record["capabilities"]["coverage"]["backgroundWorker"])

    def test_valid_v2_record(self):
        self.assertEqual([], self.errors_for(copy.deepcopy(self.valid)))

    def test_available_missing_sha256(self):
        record = copy.deepcopy(self.valid)
        del record["postgresql"]["18"]["sha256"]
        self.assert_has_error(record, "sha256")

    def test_download_url_mismatch(self):
        record = copy.deepcopy(self.valid)
        record["postgresql"]["18"]["downloadUrl"] = (
            "https://github.com/pgextwin/pg_cron/releases/download/"
            "wrong-tag/pg_cron-v1.6.8-pg18-windows-x64.zip"
        )
        self.assert_has_error(record, "downloadUrl must be")

    def test_invalid_sha256(self):
        record = copy.deepcopy(self.valid)
        record["postgresql"]["18"]["sha256"] = "not-a-sha"
        self.assert_has_error(record, "sha256")

    def test_invalid_capability_source_commit(self):
        record = copy.deepcopy(self.valid)
        record["capabilitiesSource"]["commit"] = "main"
        self.assert_has_error(record, "commit")

    def test_evidence_available_missing_asset(self):
        record = copy.deepcopy(self.valid)
        record["postgresql"]["18"]["evidence"]["sbom"] = {
            "available": True,
            "downloadUrl": (
                "https://github.com/pgextwin/pg_cron/releases/download/"
                "v1.6.8-windows.1/pg_cron-v1.6.8-pg18-windows-x64.spdx.json"
            ),
            "sha256": "0" * 64,
        }
        self.assert_has_error(record, "asset")

    def test_duplicate_functional_scenario(self):
        record = copy.deepcopy(self.valid)
        record["capabilities"]["functionalScenarios"].append(
            copy.deepcopy(record["capabilities"]["functionalScenarios"][0])
        )
        self.assert_has_error(record, "duplicate functional scenario")

    def test_forbidden_lifecycle_field(self):
        record = copy.deepcopy(self.valid)
        record["postgresql"]["18"]["eol"] = "2027-11-11"
        self.assert_has_error(record, "eol")

    def test_client_path_and_coverage_consistency(self):
        record = copy.deepcopy(self.valid)
        record["runtime"]["requirements"]["clientExecutable"] = {
            "required": True,
            "packagePaths": [],
        }
        record["capabilities"]["coverage"]["clientExecutable"] = "covered"
        self.assert_has_error(record, "client executable")

    def test_unavailable_evidence_cannot_have_artifact_fields(self):
        record = copy.deepcopy(self.valid)
        record["postgresql"]["18"]["evidence"]["vulnerabilityReport"] = {
            "available": False,
            "asset": "fictional.vulnerabilities.json",
        }
        self.assert_has_error(record, "unavailable evidence")


if __name__ == "__main__":
    unittest.main()
