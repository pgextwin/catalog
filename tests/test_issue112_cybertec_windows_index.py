"""Hostile offline tests for Cybertec metadata-only indexes (no ZIP download)."""
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_cybertec_windows_index as observer


def listing(*names):
    return ("<html><body><a href='../'>Parent</a>" +
            "".join(f"<a href='{x}'>{x}</a>" for x in names) +
            "</body></html>").encode("utf-8")


class Response:
    status = 200
    headers = {"Content-Type": "text/html; charset=UTF-8"}

    def __init__(self, url, content):
        self.url = url
        self.content = content

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def geturl(self):
        return self.url

    def read(self, n):
        return self.content[:n]


class Opener:
    def __init__(self, url, content):
        self.url = url
        self.content = content
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request.full_url, timeout))
        return Response(self.url, self.content)


class IndexTests(unittest.TestCase):
    def test_extracts_package_styles_and_keeps_all_denials(self):
        rows = observer.parse_index(listing(
            "pgvector-17-public-v0.8.2-1.zip",
            "pg_hint_plan-17-17-public-REL17_1_7_1-5-gd06add-1.zip",
            "pgtap-17-public-v1.3.4-1.zip", "pgtap.version"), "17")
        self.assertEqual({x["extension"] for x in rows},
                         {"pgvector", "pg_hint_plan", "pgtap"})
        for row in rows:
            self.assertTrue(row["originalUrlUntrusted"].startswith(observer.BASE + "17/extension/"))
            self.assertFalse(any(row[name] for name in (
                "originalBytesVerified", "originalSha256Verified",
                "upstreamVersionVerified", "communityPostgresqlAbiVerified",
                "producerProvenanceVerified", "licenseNoticeClosureVerified",
                "independentSignedAdmission", "publicGetAuthorized",
                "mirrorAuthorized", "publisherAuthorized", "releaseAuthorized")))

    def test_no_cross_major_or_duplicate(self):
        with self.assertRaisesRegex(ValueError, "major mismatch"):
            observer.parse_index(listing("pgvector-16-public-v0.8.2.zip"), "17")
        with self.assertRaisesRegex(ValueError, "major mismatch"):
            observer.parse_index(listing("pg_hint_plan-17-16-public-REL17_1_7.zip"), "17")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            observer.parse_index(listing("pgtap-17-public-v1.3.zip", "pgtap-17-public-v1.3.zip"), "17")

    def test_rejects_injection_oversize_and_empty_html(self):
        for name in ("../../evil.zip", "https://evil.test/a.zip", "pgtap%2f.zip",
                     "pgtap-17-public-v1.zip?go=true", "pgtap-17-public-v1.zip#x"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Unsafe ZIP"):
                observer.parse_index(listing(name), "17")
        for content in (b"", b"<html></html>", b"a" * (observer.MAX_INDEX_BYTES + 1)):
            with self.assertRaises(ValueError):
                observer.parse_index(content, "17")

    def test_exact_index_only_never_zip_get(self):
        url = observer.BASE + "18/extension/"
        opener = Opener(url, listing("pgtap-18-public-v1.3.4-1.zip"))
        rows = observer.fetch_index("18", opener=opener)
        self.assertEqual(rows[0]["extension"], "pgtap")
        self.assertEqual(opener.requests, [(url, 20)])
        self.assertRaises(ValueError, observer.fetch_index, "19", opener=opener)
        self.assertEqual(len(opener.requests), 1)

    def test_refuses_redirect_and_wrong_content_type(self):
        url = observer.BASE + "16/extension/"
        with self.assertRaisesRegex(ValueError, "Wrong canonical"):
            observer.fetch_index("16", opener=Opener(
                "https://attacker.test/", listing("pgtap-16-public-v1.zip")))
        x = Opener(url, listing("pgtap-16-public-v1.zip"))
        with mock.patch.object(Response, "headers", {"Content-Type": "application/zip"}):
            with self.assertRaisesRegex(ValueError, "media type"):
                observer.fetch_index("16", opener=x)
        with self.assertRaisesRegex(ValueError, "redirect"):
            observer.NoRedirect().redirect_request(None, None, 301, "redirect", {}, url)

    def test_coverage_is_names_only_not_abi_or_latest(self):
        rows = {m: observer.parse_index(listing(f"pgtap-{m}-public-v1.3.4-1.zip"), m)
                for m in observer.MAJORS}
        result = observer.collect(rows)
        self.assertEqual(result["completeObservedFiveMajorNames"], ["pgtap"])
        self.assertEqual(result["latestVersionResolution"], "NOT_VERIFIED")
        self.assertFalse(result["publicGetAuthorized"])
        self.assertFalse(result["releaseAuthorized"])
        rows["18"][0]["publicGetAuthorized"] = True
        with self.assertRaisesRegex(ValueError, "trust escalation"):
            observer.collect(rows)


if __name__ == "__main__":
    unittest.main()
