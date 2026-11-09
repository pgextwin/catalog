#!/usr/bin/env python3
"""Malicious-input regression for authentic immutable public GET-only pin checks."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "get_pin_validator", ROOT / "scripts/validate_public_get_pin.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
NOW = datetime(2026, 11, 8, 0, 0, 1, tzinfo=timezone.utc)

def example():
    return {
        "schemaVersion": "pgextwin-external-direct-get-admission/v1",
        "sourceKind": "EXTERNAL_GITHUB_RELEASE_ASSET",
        "issuerRepository": "pgextwin/build",
        "issuerCommit": "a" * 40, "catalogCommit": "b" * 40,
        "issuerEvent": "workflow_dispatch", "issuerRunId": 1234,
        "issuerRunAttempt": 1, "ownerActor": "ShutenOishi",
        "ownerId": 27071164, "publisherEnvironment": "external-direct-provider-publisher",
        "publisherAppId": 5609317, "approvedOperation": "ORIGINAL_PROVIDER_GET_ONLY",
        "issuedAt": "2026-11-08T00:00:00Z",
        "expiresAt": "2026-11-08T06:00:00Z",
        "downloadAuthorized": True, "mirrorAuthorized": False,
        "redistributionAuthorized": False,
        "records": [{
            "sourceGroup": "external", "extension": "pg_trickle", "pgMajor": "18",
            "targetEnvironment": "EDB PostgreSQL 18.6.5 Windows x64",
            "sourceRepo": "trickle-labs/pg-trickle", "repositoryId": 1164857056,
            "releaseTag": "v0.108.3", "releaseId": 404988260,
            "assetName": "pg_trickle-0.108.3-pg18-windows-amd64.zip",
            "assetId": 616203967, "originalBytes": 7029107,
            "originalSha256": "c2841dacee6fa1a09400c7e9a0f74159f2b7f36847a60ef10291d1beb06bd96b",
            "originalProviderUrl":
                "https://github.com/trickle-labs/pg-trickle/releases/download/v0.108.3/"
                "pg_trickle-0.108.3-pg18-windows-amd64.zip",
            "licenseUrl": "https://github.com/trickle-labs/pg-trickle/blob/v0.108.3/LICENSE",
            "noticeTreatment": "Original Apache 2.0 LICENSE and upstream NOTICE references remain visible.",
            "dependencyTreatment": "The user must install runtime prerequisites separately, not redistributed.",
            "approvedOperation": "ORIGINAL_PROVIDER_GET_ONLY",
            "downloadAuthorized": True, "mirrorAuthorized": False,
        }],
    }

def qualified_cohort_example():
    """Offline shape fixture: archived originals are NOT current authorization."""
    doc = example()
    rows = []
    for source, runid in (
        ("pg_trickle", 42493106193),
        ("hypopg", 42484873648),
        ("portalcorp_pgvector", 42545790345),
    ):
        path = (ROOT / "external/signed-direct-get" / source / f"run-{runid}"
                / "external-get-admission.json")
        rows.extend(json.loads(path.read_text("utf-8"))["records"])
    doc["records"] = rows
    return doc

class Tests(unittest.TestCase):
    def test_missing_public_pin_is_nonpublishing_noop(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(mod.scan(t, now=NOW, online=False), [])

    def test_fixed_scope_and_six_hour_lifetime(self):
        self.assertEqual(mod.validate_document(example(), "run-1234", now=NOW), "ACTIVE")
        self.assertEqual(mod.validate_document(example(), "run-1234",
            now=NOW + timedelta(hours=10)), "EXPIRED_ARCHIVE_DOWNLOAD_DENY")
        d = example()
        for key, val in [
            ("issuerRunId", 1235), ("issuerRunAttempt", 2),
            ("ownerId", 1), ("issuerRepository", "attacker/repo"),
            ("issuerCommit", "g" * 40), ("publisherAppId", 5451798),
            ("approvedOperation", "MIRROR"), ("downloadAuthorized", False),
            ("mirrorAuthorized", True), ("redistributionAuthorized", True),
            ("expiresAt", "2026-11-09T00:00:00Z"), ("unknown", True),
        ]:
            with self.subTest(field=key):
                changed = copy.deepcopy(d)
                changed[key] = val
                with self.assertRaises(mod.Denied):
                    mod.validate_document(changed, "run-1234", now=NOW)
        for key, val in [
            ("sourceRepo", "laurenz/oracle_fdw"), ("assetId", 1),
            ("originalBytes", 1), ("pgMajor", "17"), ("mirrorAuthorized", True),
            ("downloadAuthorized", False), ("originalSha256", "0" * 64),
            ("assetName", "not-original.zip"), ("originalProviderUrl", "https://evil.invalid/zip"),
            ("noticeTreatment", ""), ("unexpected", "yes"),
        ]:
            with self.subTest(row=key):
                changed = copy.deepcopy(d)
                changed["records"][0][key] = val
                with self.assertRaises(mod.Denied):
                    mod.validate_document(changed, "run-1234", now=NOW)

    def test_exact_two_file_layout_and_expired_archive(self):
        with tempfile.TemporaryDirectory() as t:
            archive = Path(t) / "external/signed-direct-get/pg_trickle/run-1234"
            archive.mkdir(parents=True)
            (archive / "external-get-admission.json").write_text(
                json.dumps(example(), sort_keys=True) + "\n")
            (archive / "attestation.json").write_bytes(b"x" * 200)
            entries = mod.scan(t, now=NOW, online=False)
            self.assertEqual(entries[0]["status"], "ACTIVE")
            self.assertEqual(mod.scan(t, now=NOW + timedelta(days=1),
                                      online=False)[0]["status"],
                             "EXPIRED_ARCHIVE_DOWNLOAD_DENY")
            (archive / "rogue.zip").write_bytes(b"x")
            with self.assertRaises(mod.Denied):
                mod.scan(t, now=NOW, online=False)

    def test_no_alternate_source_or_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "external/signed-direct-get"
            (p / "oracle_fdw").mkdir(parents=True)
            with self.assertRaises(mod.Denied):
                mod.scan(t, now=NOW, online=False)
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "external/signed-direct-get"
            p.mkdir(parents=True)
            (p / "pg_trickle").symlink_to(Path(t), target_is_directory=True)
            with self.assertRaises(mod.Denied):
                mod.scan(t, now=NOW, online=False)

    def test_exact_five_asset_mixed_source_cohort(self):
        doc = qualified_cohort_example()
        self.assertEqual(len(doc["records"]), 5)
        self.assertEqual(mod.validate_document(doc, "run-1234", now=NOW,
                         source="qualified_cohort"), "ACTIVE")
        self.assertEqual(mod.validate_document(doc, "run-1234",
                         now=NOW + timedelta(hours=7),
                         source="qualified_cohort"), "EXPIRED_ARCHIVE_DOWNLOAD_DENY")
        mutations = [
            lambda r: r.pop(),
            lambda r: r.append(copy.deepcopy(r[0])),
            lambda r: r.reverse(),
            lambda r: r[1].update({"pgMajor": "17"}),
            lambda r: r[2].update({"originalSha256": "0" * 64}),
            lambda r: r[4].update({"sourceRepo": "laurenz/oracle_fdw"}),
            lambda r: r[0].update({"mirrorAuthorized": True}),
            lambda r: r[4].update({"noticeTreatment": ""}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                bad = copy.deepcopy(doc)
                mutate(bad["records"])
                with self.assertRaises(mod.Denied):
                    mod.validate_document(bad, "run-1234", now=NOW,
                                          source="qualified_cohort")

    def test_mixed_source_offline_fixture_cannot_pass_online_authentication(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as t:
            archive = (Path(t) / "external/signed-direct-get/qualified_cohort/run-1234")
            archive.mkdir(parents=True)
            (archive / "external-get-admission.json").write_text(
                json.dumps(qualified_cohort_example(), sort_keys=True) + "\\n")
            (archive / "attestation.json").write_bytes(b"x" * 200)
            with patch.object(mod, "gh_read", side_effect=mod.Denied("no live owner proof")):
                with self.assertRaises(mod.Denied):
                    mod.scan(t, now=NOW, online=True)

    def test_integration_is_required_in_catalog_validate_job(self):
        workflow = (ROOT / ".github/workflows/validate.yml").read_text("utf-8")
        # Existing required validate job has no PyYAML; no new dependency.
        self.assertIn(
            "run: python scripts/validate_public_get_pin.py --catalog .",
            workflow)
        self.assertIn("GH_TOKEN: "+chr(36)+"{{ github.token }}", workflow)
        linux_job, windows_job = workflow.split("  cli-windows-package-smoke:", 1)
        self.assertEqual(
            linux_job.count("scripts/validate_public_get_pin.py --catalog ."), 1)
        self.assertEqual(
            windows_job.count("scripts/validate_public_get_pin.py --catalog ."), 1)

if __name__ == "__main__":
    unittest.main()
