"""Hostile/offline proof that Cybertec original inspection cannot authorize release."""
from io import BytesIO
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import issue112_cybertec_permissions_original as v

CONTROL = b"default_version = '1.4'\nrelocatable = false\n"
SQL = b'-- synthetic fixture only\nSELECT 1;\n'


def synthetic_files():
    return {'share/extension/' + n: CONTROL if n.endswith('.control') else SQL
            for n in v.REQUIRED}


def zipped(files=None):
    stream = BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as z:
        for k, value in (synthetic_files() if files is None else files).items():
            z.writestr(k, value)
    return stream.getvalue()


class Reply:
    status = 200
    def __init__(self, url, data, media='application/zip', length=None):
        self.url, self.data = url, data
        self.headers = {'Content-Type': media,
                        'Content-Length': str(len(data) if length is None else length)}
    def geturl(self): return self.url
    def read(self, n): return self.data[:n]
    def __enter__(self): return self
    def __exit__(self, *args): pass


class Opener:
    def __init__(self, reply): self.reply = reply
    def open(self, request, timeout):
        assert timeout == 45
        return self.reply


class Tests(unittest.TestCase):
    def test_url_label_must_not_be_1_4_1(self):
        for pg in v.MAJORS:
            url = v.original_url(pg)
            self.assertTrue(url.endswith('pg_permissions-'+pg+'-public-REL_1_4-1.zip'))
            self.assertNotIn('1_4_1', url)
        with self.assertRaisesRegex(ValueError, 'Unsupported'):
            v.original_url('19')

    def test_sha_crc_members_and_all_denials(self):
        result, _ = v.review_zip(zipped(), '14')
        self.assertEqual(result['providerOriginalPackageLabel'], 'REL_1_4')
        self.assertEqual(result['sqlExtensionDefaultVersion'], '1.4')
        self.assertEqual(len(result['installableSqlAndControl']), 8)
        self.assertEqual(len(result['originalSha256']), 64)
        self.assertEqual(result['zipCrc'], 'PASS')
        for flag in v.DENIALS:
            self.assertIs(result[flag], False)

    def test_source_identity_not_fabricated(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            for n in v.REQUIRED:
                (base / n).write_bytes(CONTROL if n.endswith('.control') else SQL)
            good, found = v.review_zip(zipped(), '17', base)
            self.assertTrue(good['completeSourceSqlControlMatch'])
            self.assertEqual(len(good['sourceExactByteMatches']), 8)
            stage = base / 'staged'
            v.stage_verified(found, stage)
            self.assertEqual((stage / 'pg_permissions.control').read_bytes(), CONTROL)
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                v.stage_verified(found, stage)
            (base / 'pg_permissions--1.2.sql').write_bytes(b'modified')
            wrong, _ = v.review_zip(zipped(), '17', base)
            self.assertFalse(wrong['completeSourceSqlControlMatch'])
            self.assertEqual(wrong['sourceByteDiffers'], ['pg_permissions--1.2.sql'])

    def test_bad_paths_and_duplicate_installable_refused(self):
        for name in ('../escape/pg_permissions.control', 'C:/pg_permissions.control',
                     '..\\pg_permissions.control'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Unsafe'):
                files = synthetic_files(); files[name] = CONTROL
                v.review_zip(zipped(files), '15')
        with self.assertRaisesRegex(ValueError, 'Duplicate installable'):
            files = synthetic_files(); files['elsewhere/pg_permissions.control'] = CONTROL
            v.review_zip(zipped(files), '15')

    def test_missing_extra_and_control_version_fail_closed(self):
        files = synthetic_files(); files.pop('share/extension/pg_permissions--1.1.sql')
        with self.assertRaisesRegex(ValueError, 'Missing'):
            v.review_zip(zipped(files), '18')
        files = synthetic_files(); files['one/pg_permissions--1.5.sql'] = SQL
        with self.assertRaisesRegex(ValueError, 'Missing'):
            v.review_zip(zipped(files), '16')
        files = synthetic_files(); files['share/extension/pg_permissions.control'] = b"default_version = '1.4.1'\n"
        with self.assertRaisesRegex(ValueError, 'default version'):
            v.review_zip(zipped(files), '14')

    def test_redirect_media_truncation(self):
        url = v.original_url('17'); raw = zipped()
        for reply, error in ((Reply('https://else.invalid/a.zip', raw), 'redirect'),
                             (Reply(url, raw, 'text/html'), 'media type'),
                             (Reply(url, raw, length=len(raw)+3), 'truncated')):
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                v.review_original('17', opener=Opener(reply))
        result, _ = v.review_original('17', opener=Opener(Reply(url, raw)))
        self.assertFalse(result['publicGetAuthorized'])
        with self.assertRaisesRegex(ValueError, 'Redirected'):
            v.NoRedirect().redirect_request(None, None, 302, 'redirect', {}, url)

    def test_expansion_and_oversize(self):
        with self.assertRaisesRegex(ValueError, 'oversized'):
            v.review_zip(b'x' * (v.MAX_ZIP + 1), '14')
        files = synthetic_files(); files['verylarge.txt'] = b'x' * 500000
        with self.assertRaisesRegex(ValueError, 'expansion'):
            v.review_zip(zipped(files), '14')

    def test_source_symlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(Path, 'is_symlink', lambda p: p.name == 'pg_permissions.control'):
                with self.assertRaisesRegex(ValueError, 'Linked'):
                    v.review_zip(zipped(), '16', d)


if __name__ == '__main__':
    unittest.main()
