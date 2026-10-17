#!/usr/bin/env python3
"""Offline hostile probe tests: browser or Action tokens must never leak."""
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_original_log_access_probe as probe


class OriginalPublicLogAccessTests(unittest.TestCase):
    def test_only_approved_redirect_hosts_and_tls(self):
        for url in (
            "https://api.github.com/logs",
            "https://pipelines.actions.githubusercontent.com/example",
            "https://example.blob.core.windows.net/path",
            "https://files.githubusercontent.com/logs",
        ):
            self.assertTrue(probe.is_github_delivery(url), url)
        for url in (
            "http://api.github.com/logs",
            "https://evil.githubusercontent.com.attacker.example/log",
            "https://api.github.com.evil.example/logs",
            "ftp://pipelines.actions.githubusercontent.com/log",
            "https://example.invalid/log",
        ):
            self.assertFalse(probe.is_github_delivery(url), url)

    def test_no_app_token_sent_to_public_signed_redirect(self):
        seen = []
        class Response(io.BytesIO):
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *_):
                self.close()
        class Opener:
            def open(self, request, timeout=None):
                seen.append(request)
                raise HTTPError(probe.URL, 302, "moved", {
                    "Location": "https://pipelines.actions.githubusercontent.com/signed"
                }, None)
        def redirect(request, timeout=None):
            seen.append(request)
            return Response(b"original public log text")
        with patch.object(probe, "build_opener", return_value=Opener()), \
             patch.object(probe, "urlopen", side_effect=redirect):
            r = probe.initial_get("DO_NOT_LEAK_EPHEMERAL_APP_TOKEN")
        self.assertEqual(r["first"], 302)
        self.assertEqual(r["redirect"], "allowed_https")
        self.assertEqual(r["delivery_http"], 200)
        self.assertEqual(r["bytes"], len(b"original public log text"))
        self.assertIn("Authorization", seen[0].headers)
        self.assertNotIn("Authorization", seen[1].headers)
        self.assertEqual(seen[1].get_method(), "GET")
        self.assertNotIn("DO_NOT_LEAK", str(r))

    def test_reject_untrusted_redirect_before_get(self):
        class Opener:
            def open(self, *_a, **_kw):
                raise HTTPError(probe.URL, 302, "moved", {
                    "Location": "https://evil.invalid/steal"
                }, None)
        with patch.object(probe, "build_opener", return_value=Opener()), \
             patch.object(probe, "urlopen") as get:
            out = probe.initial_get("secret")
        self.assertEqual(out["redirect"], "unapproved")
        get.assert_not_called()

    def test_fail_closed_no_network(self):
        class Opener:
            def open(self, *_a, **_kw):
                raise OSError("no network")
        with patch.object(probe, "build_opener", return_value=Opener()):
            out = probe.initial_get()
        self.assertEqual(out["bytes"], 0)
        self.assertNotIn("success", str(out).lower())


if __name__ == "__main__":
    unittest.main()
