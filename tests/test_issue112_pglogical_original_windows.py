"""Offline adversarial checks for the nonpublishing pglogical original intake."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "pglogical_candidate_audit", ROOT / "scripts/issue112_pglogical_original_windows.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def fake_pe():
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x98, 0x20b)
    return bytes(data)


def fixture(extra=None, corrupt_info=None):
    info = {
        "pglogicalVersion": "2.4.8",
        "postgresqlCompatibilityMajor": 18,
        "upstreamTag": "REL2_4_8",
        "upstreamCommitSha": audit.UPSTREAM_COMMIT,
        "windowsPackagingRevision": 1,
        "edbArtifactCalculatedSha256": "a" * 64,
    }
    info.update(corrupt_info or {})
    content = {
        "BUILD-INFO.json": json.dumps(info).encode(),
        "share/pglogical/COPYRIGHT": b"PostgreSQL License and full copyright notice " * 6,
        "lib/pglogical.dll": fake_pe(),
        "lib/pglogical_output.dll": fake_pe(),
        "bin/pglogical_create_subscriber.exe": fake_pe(),
        "share/extension/pglogical.control": b"default_version='2.4.8'",
        "share/extension/pglogical_origin.control": b"default_version='1.0.0'",
        "share/extension/pglogical_origin--1.0.0.sql": b"select 1;",
        "share/extension/pglogical--2.4.8.sql": b"select 1;",
    }
    content.update(extra or {})
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as z:
        for path, contents in content.items():
            z.writestr(path, contents)
    return data.getvalue()


class PgLogicalOriginalAdversarialTests(unittest.TestCase):
    def test_exact_five_pin_registry_is_deny_only(self):
        for major, (asset_id, length, digest) in audit.PINS.items():
            audit.validate_source_registry(major, asset_id, length, digest)
        self.assertEqual({14, 15, 16, 17, 18}, set(audit.PINS))
        self.assertEqual(audit.REPO_ID, 1324318750)

    def test_provider_api_root_has_no_trailing_slash(self):
        expected = "https://api.github.com/repos/semihkiroglu/pglogical-windows"
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc, tb):
                return False
            def geturl(self):
                return expected
            def read(self, limit):
                return b'{"id":1324318750}'
        def fake_open(request, timeout):
            self.assertEqual(request.full_url, expected)
            self.assertEqual(timeout, 30)
            return Response()
        with patch.object(audit.urllib.request, "urlopen", side_effect=fake_open):
            self.assertEqual(audit.api_json("").get("id"), audit.REPO_ID)

    def test_valid_amd64_and_package_fixture(self):
        self.assertTrue(audit.pe_x64(fake_pe()))
        self.assertFalse(audit.pe_x64(b"MZ" + bytes(200)))
        self.assertIn("lib/pglogical.dll", audit.inspect_zip(fixture(), 18))

    def test_cross_major_and_wrong_commit_deny(self):
        with self.assertRaises(ValueError):
            audit.inspect_zip(fixture(), 17)
        with self.assertRaises(ValueError):
            audit.inspect_zip(fixture(corrupt_info={"upstreamCommitSha": "0" * 40}), 18)

    def test_unsafe_paths_and_unknown_payload_deny(self):
        for name in ("../attack.dll", "lib/../../evil.dll", "/tmp/evil.dll",
                     "lib\\pglogical.dll", "lib/untrusted.dll",
                     "bin/postgres.exe", "share/extension/other.control"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                audit.inspect_zip(fixture({name: b"untrusted"}), 18)

    def test_no_license_or_missing_core_deny(self):
        content = fixture()
        # Exact fixtures include notice; stripping it must deny.
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            payload = {i.filename: archive.read(i) for i in archive.infolist()
                       if i.filename != "share/pglogical/COPYRIGHT"}
        with self.assertRaises(ValueError):
            audit.inspect_zip(fixture_without_notice(payload), 18)

    def test_archive_not_authorization(self):
        workflow = (ROOT / ".github/workflows/issue112-pglogical-original-windows.yml").read_text()
        self.assertIn("pull_request:", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("create-release", workflow)
        self.assertNotIn("publisher", workflow.lower().split("jobs:", 1)[1])


def fixture_without_notice(payload):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as z:
        for name, contents in payload.items():
            z.writestr(name, contents)
    return data.getvalue()


if __name__ == "__main__":
    unittest.main()
