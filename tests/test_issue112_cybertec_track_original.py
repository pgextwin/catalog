"""Offline hostile tests for source-pinned Cybertec original ZIP observer."""
from io import BytesIO
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_cybertec_track_original as verifier

CONTROL = b"default_version = '2.1.2'\nrelocatable = false\n"
SQL = b"-- test SQL\nCREATE TABLE example (i int);\n"


def package(files=None):
    if files is None:
        files = {"share/extension/pg_track_settings.control": CONTROL,
                 "share/extension/pg_track_settings--2.1.2.sql": SQL,
                 "LICENSE": b"PostgreSQL License"}
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return stream.getvalue()


class Response:
    status = 200
    def __init__(self, url, data, content_type="application/zip", length=None):
        self.url, self.data = url, data
        self.headers = {"Content-Type": content_type,
                        "Content-Length": str(len(data) if length is None else length)}
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def geturl(self):
        return self.url
    def read(self, count):
        return self.data[:count]


class Opener:
    def __init__(self, reply):
        self.reply, self.urls = reply, []
    def open(self, request, timeout):
        self.urls.append((request.full_url, timeout))
        return self.reply


class PrivateOriginalTests(unittest.TestCase):
    def test_original_sha_and_public_denials(self):
        result = verifier.review_zip(package(), "16")
        self.assertEqual(len(result["originalSha256"]), 64)
        self.assertEqual(result["zipCrc"], "PASS")
        self.assertEqual(result["status"], "CANDIDATE_ONLY")
        self.assertEqual(result["packagedLicenseNoticeMembers"], ["LICENSE"])
        self.assertEqual(len(result["installableSqlAndControl"]), 2)
        for key in verifier.DENIALS:
            self.assertIs(result[key], False)

    def test_exact_pinned_upstream_match_and_modified_fail_closed_as_claim(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / "pg_track_settings.control").write_bytes(CONTROL)
            (p / "pg_track_settings--2.1.2.sql").write_bytes(SQL)
            yes = verifier.review_zip(package(), "18", p)
            self.assertTrue(yes["upstreamCompleteSqlControlMatch"])
            self.assertEqual(len(yes["upstreamExactByteMatches"]), 2)
            (p / "pg_track_settings--2.1.2.sql").write_bytes(b"-- altered\n")
            no = verifier.review_zip(package(), "18", p)
            self.assertFalse(no["upstreamCompleteSqlControlMatch"])
            self.assertEqual(no["upstreamByteDiffers"], ["pg_track_settings--2.1.2.sql"])
            self.assertFalse(no["publicGetAuthorized"])

    def test_reject_bad_paths_and_duplicate_installables(self):
        for name in ("../evil/pg_track_settings--2.1.2.sql", 
                     "C:/pg_track_settings--2.1.2.sql",
                     r"..\pg_track_settings--2.1.2.sql"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Unsafe"):
                verifier.review_zip(package({
                    "share/extension/pg_track_settings.control": CONTROL,
                    name: SQL}), "14")
        with self.assertRaisesRegex(ValueError, "Duplicate installable"):
            verifier.review_zip(package({
                "a/pg_track_settings.control": CONTROL,
                "b/pg_track_settings.control": CONTROL,
                "c/pg_track_settings--2.1.2.sql": SQL}), "14")

    def test_reject_missing_or_wrong_version(self):
        with self.assertRaisesRegex(ValueError, "absent"):
            verifier.review_zip(package({"pg_track_settings.control": CONTROL,
                                         "other.sql": SQL}), "15")
        with self.assertRaisesRegex(ValueError, "default version"):
            verifier.review_zip(package({
                "pg_track_settings.control": b"default_version = '2.1.1'",
                "pg_track_settings--2.1.2.sql": SQL}), "15")
        with self.assertRaisesRegex(ValueError, "Unsupported PG"):
            verifier.original_url("19")

    def test_redirect_media_type_and_truncation_fail(self):
        url = verifier.original_url("17")
        contents = package()
        for response, reason in (
            (Response("https://elsewhere.invalid/evil.zip", contents), "redirect"),
            (Response(url, contents, "text/html"), "media type"),
            (Response(url, contents, length=len(contents) + 1), "Truncated"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                verifier.review_original("17", opener=Opener(response))
        good = Opener(Response(url, contents))
        result = verifier.review_original("17", opener=good)
        self.assertEqual(good.urls, [(url, 45)])
        self.assertFalse(result["releaseAuthorized"])
        with self.assertRaisesRegex(ValueError, "Redirected"):
            verifier.NoRedirect().redirect_request(None, None, 302, "redirect", {}, url)

    def test_reject_oversize_bomb_and_crc(self):
        with self.assertRaisesRegex(ValueError, "too large"):
            verifier.review_zip(b"x" * (verifier.MAX_ZIP + 1), "14")
        with self.assertRaisesRegex(ValueError, "expansion limit"):
            verifier.review_zip(package({
                "pg_track_settings.control": CONTROL,
                "pg_track_settings--2.1.2.sql": b"z" * 300000}), "14")
        raw = bytearray(package())
        start = raw.find(SQL)
        if start >= 0:
            raw[start] ^= 1
            with self.assertRaises((ValueError, zipfile.BadZipFile)):
                verifier.review_zip(bytes(raw), "14")

    def test_source_link_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            # Also exercise Windows runners without SeCreateSymbolicLinkPrivilege.
            with mock.patch.object(Path, "is_symlink", lambda q: q.name == "pg_track_settings.control"):
                with self.assertRaisesRegex(ValueError, "Linked upstream"):
                    verifier.review_zip(package(), "16", p)


if __name__ == "__main__":
    unittest.main()
