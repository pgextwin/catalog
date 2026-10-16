#!/usr/bin/env python3
"""Offline hostile tests for anonymous GET transport; no real network or signatures."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import distribution_p1_anonymous_get as transport
import distribution_release_verify_p1 as verifier
from distribution_manifest_v1 import Denied


ZIP = b"untrusted fixture bytes"
DIGEST = hashlib.sha256(ZIP).hexdigest()
TAG = "v1.0-windows.1"
TARGET = "a" * 40
NAME = "pg_bigm-v1.0-pg14-windows-x64.zip"
ARGS = dict(repo_id=123, release_id=456, asset_id=789, asset_sha=DIGEST,
            asset_size=len(ZIP), target_sha=TARGET, tag=TAG)


def fake_api(path):
    if path == "repos/pgextwin/pg_bigm":
        return {"id": 123, "full_name": "pgextwin/pg_bigm"}
    if path == "repos/pgextwin/pg_bigm/releases/456":
        return {"id": 456, "tag_name": TAG, "target_commitish": TARGET,
                "draft": False, "prerelease": False,
                "assets": [{"id": 789, "name": NAME, "size": len(ZIP),
                            "state": "uploaded", "digest": "sha256:" + DIGEST,
                            "browser_download_url":
                            "https://github.com/pgextwin/pg_bigm/releases/download/"
                            + TAG + "/" + NAME}]}
    if path == "repos/pgextwin/pg_bigm/attestations/sha256:" + DIGEST:
        return {"attestations": [{"repository_id": 123,
                   "bundle": {"dsseEnvelope": {"payload": "fixture"},
                              "verificationMaterial": {"fixture": True}}}]}
    raise AssertionError("unexpected URL: " + path)


def fake_fetch(url, *, kind, accept, limit, expected_size=None):
    assert kind == "asset" and expected_size == len(ZIP)
    return ZIP


class HttpResponse:
    def __init__(self, status, body, headers=None):
        self.status = status
        self.body = io.BytesIO(body)
        self.headers = headers or {}
    def read(self, n):
        return self.body.read(n)
    def close(self):
        self.body.close()


class AnonymousGetTests(unittest.TestCase):
    def get_case(self, mutate=None, byte_change=None, **changed):
        def api(path):
            data = fake_api(path)
            if mutate is not None and path.endswith("/releases/456"):
                mutate(data)
            return data
        args = dict(ARGS, **changed)
        with tempfile.TemporaryDirectory() as d:
            with patch.object(transport, "_api", side_effect=api), \
                 patch.object(transport, "_response",
                              side_effect=(byte_change or fake_fetch)):
                return transport.acquire("pg_bigm", destination=Path(d), **args)

    def test_success_is_only_unverified_transport(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(transport, "_api", side_effect=fake_api), \
                 patch.object(transport, "_response", side_effect=fake_fetch):
                result = transport.acquire("pg_bigm", destination=Path(d), **ARGS)
                self.assertEqual(result["verificationLevel"], "UNVERIFIED")
                self.assertFalse(result["publicationAuthorized"])
                self.assertEqual((Path(d) / NAME).read_bytes(), ZIP)
                lines = (Path(d) / (NAME+".jsonl")).read_text().splitlines()
                self.assertEqual(len(lines), 1)
                self.assertIn("bundle", json.loads(lines[0]))
                with self.assertRaises(Denied):
                    transport.acquire("pg_bigm", destination=Path(d), **ARGS)

    def test_identity_spoofing_denied(self):
        for changes in ({"repo_id": 1}, {"release_id": 1},
                        {"asset_id": 1}, {"asset_sha": "f"*64},
                        {"asset_size": len(ZIP)+1},
                        {"target_sha": "b"*40},
                        {"tag": "v1.0-windows.2"}):
            with self.subTest(changes=changes), self.assertRaises(Denied):
                self.get_case(**changes)

    def test_asset_metadata_substitution_denied(self):
        attacks = (
            lambda r: r["assets"][0].update(id=799),
            lambda r: r["assets"][0].update(name="../../evil.zip"),
            lambda r: r["assets"][0].update(digest="sha256:"+"f"*64),
            lambda r: r["assets"][0].update(browser_download_url="https://evil.invalid/x"),
            lambda r: r["assets"][0].update(size=len(ZIP)+1),
            lambda r: r["assets"].append(dict(r["assets"][0])),
            lambda r: r.update(draft=True),
            lambda r: r.update(target_commitish="b"*40),
        )
        for index, mutate in enumerate(attacks):
            with self.subTest(case=index), self.assertRaises(Denied):
                self.get_case(mutate=mutate)

    def test_actual_byte_substitution_denied(self):
        with self.assertRaises(Denied):
            self.get_case(byte_change=lambda *a, **kw: ZIP+b"tampered")

    def test_missing_duplicate_or_wrong_repo_attestation_denied(self):
        for bad in ({"attestations": []},
                    {"attestations": [{"repository_id": 9, "bundle": {}}]},
                    {"attestations": [
                       {"repository_id": 123, "bundle": {
                           "dsseEnvelope": {}, "verificationMaterial": {}}},
                       {"repository_id": 123, "bundle": {
                           "dsseEnvelope": {}, "verificationMaterial": {}}}]}):
            def api(path, bad=bad):
                if "/attestations/" in path:
                    return bad
                return fake_api(path)
            with tempfile.TemporaryDirectory() as d:
                with patch.object(transport, "_api", side_effect=api), \
                     patch.object(transport, "_response", side_effect=fake_fetch):
                    with self.assertRaises(Denied):
                        transport.acquire("pg_bigm", destination=Path(d), **ARGS)

    def test_forbidden_origins_and_urls(self):
        for url, kind in (
            ("http://api.github.com/repos/pgextwin/x", "api"),
            ("https://evil.invalid/file.zip", "asset"),
            ("https://api.github.com.evil.invalid/x", "api"),
            ("https://127.0.0.1/file", "asset"),
            ("https://user:pass@api.github.com/repos/pgextwin/x", "api"),
            ("https://evil.blob.core.windows.net.evil.invalid/f", "bundle"),
            ("https://api.github.com:8443/repos/pgextwin/x", "api"),
        ):
            with self.subTest(url=url), self.assertRaises(Denied):
                transport._allowed(url, kind)

    def test_partial_and_truncated_http_denied(self):
        url = "https://api.github.com/repos/pgextwin/example"
        cases = [HttpResponse(206, b"abc", {"Content-Range": "bytes 0-2/5"}),
                 HttpResponse(200, b"abc", {"Content-Length": "8"}),
                 HttpResponse(200, b"abc", {"Content-Length": str(transport.MAX_JSON+1)})]
        for resp in cases:
            with patch.object(transport._OPENER, "open", return_value=resp):
                with self.assertRaises(Denied):
                    transport._response(url, kind="api", accept="application/json",
                                        limit=transport.MAX_JSON)

    def test_redirect_unsafe_or_excessive_denied(self):
        url = "https://api.github.com/repos/pgextwin/example"
        error = HTTPError(url, 302, "redirect",
                          {"Location": "https://evil.invalid/malware"}, None)
        with patch.object(transport._OPENER, "open", side_effect=error):
            with self.assertRaises(Denied):
                transport._response(url, kind="api",
                                    accept="application/json", limit=1024)
        loop = HTTPError(url, 302, "redirect", {"Location": url}, None)
        with patch.object(transport._OPENER, "open", side_effect=loop):
            with self.assertRaises(Denied):
                transport._response(url, kind="api",
                                    accept="application/json", limit=1024)

    def test_auth_failure_denied_no_fallback(self):
        url = "https://api.github.com/repos/pgextwin/example"
        for status in (401, 403, 404, 429, 500):
            with patch.object(transport._OPENER, "open",
                              side_effect=HTTPError(url, status, "denied", {}, None)):
                with self.subTest(code=status), self.assertRaises(Denied):
                    transport._response(url, kind="api",
                                        accept="application/json", limit=1024)

    def test_new_release_full_sha_not_relaxed(self):
        config = {"name": "pg_bigm", "postgresql": {"majors": [14]},
                  "upstream": {"repository": "pgbigm/pg_bigm",
                               "ref": "v1.0", "version": "1.0"}}
        record = {"name": "pg_bigm", "upstream": {
            "repository": "pgbigm/pg_bigm", "ref": "v1.0", "version": "1.0"}}
        with self.assertRaises(Denied):
            verifier.immutable_source(config, 14, record)
        with self.assertRaises(Denied):
            verifier.signed_run({"id": 567, "run_attempt": 1,
                                 "repository": {"id": 123, "full_name": "pgextwin/pg_bigm"},
                                 "head_sha": TARGET, "head_branch": "main",
                                 "event": "workflow_dispatch",
                                 "path": ".github/workflows/promote.yml",
                                 "status": "completed", "conclusion": "failure",
                                 "actor": {"login": "human"}},
                                repo="pgextwin/pg_bigm", repo_id=123,
                                packaging_sha=TARGET, run_id=567, attempt=1)


if __name__ == "__main__":
    unittest.main()
