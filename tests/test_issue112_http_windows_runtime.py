"""Offline adversarial staging tests; never download or run candidate DLLs."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import issue112_http_windows_runtime as runtime


def pe64():
    data = bytearray(256)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<H', data, 132, 0x8664)
    return data


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'host'
        self.root.mkdir()
        self.zip = Path(self.tmp.name) / 'original.zip'

    def make_zip(self, extra=None, prefix='pg18http_w64/', sql=True):
        files = {'lib/http.dll': pe64(), 'share/extension/http.control': b"default_version='1.7.1'"}
        if sql:
            files['share/extension/http--1.7.1.sql'] = b'-- SQL'
        files.update(extra or {})
        with zipfile.ZipFile(self.zip, 'w') as archive:
            for name, data in files.items():
                archive.writestr(prefix + name, data)

    def test_host_dependency_preserved_and_extra_depends_excluded(self):
        (self.root / 'bin').mkdir()
        host = self.root / 'bin/libcurl.dll'
        host.write_bytes(b'EDB original host')
        self.make_zip({'bin/libcurl.dll': b'other curl', 'extra_depends/extra.dll': b'omit'})
        _, receipts = runtime.stage_archive(self.zip, self.root, '18')
        row = next(r for r in receipts if r['zipMember'].endswith('/bin/libcurl.dll'))
        self.assertTrue(row['existingHostPreserved'])
        self.assertEqual(host.read_bytes(), b'EDB original host')
        self.assertNotEqual(row['originalMemberSha256'], row['effectiveFileSha256'])
        self.assertFalse((self.root / 'extra_depends').exists())
        self.assertEqual(runtime.digest(self.root / 'lib/http.dll'), hashlib.sha256(pe64()).hexdigest())

    def test_extension_collision_fails_before_any_write(self):
        (self.root / 'lib').mkdir()
        (self.root / 'lib/http.dll').write_bytes(b'keep')
        self.make_zip({'bin/probe.dll': b'new'})
        with self.assertRaisesRegex(ValueError, 'collision'):
            runtime.stage_archive(self.zip, self.root, '18')
        self.assertEqual((self.root / 'lib/http.dll').read_bytes(), b'keep')
        self.assertFalse((self.root / 'bin').exists())

    def test_wrong_major_layout_fails(self):
        self.make_zip(prefix='pg17http_w64/')
        with self.assertRaisesRegex(ValueError, 'layout'):
            runtime.stage_archive(self.zip, self.root, '18')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_missing_sql_fails_before_writes(self):
        self.make_zip(sql=False)
        with self.assertRaisesRegex(ValueError, 'SQL'):
            runtime.stage_archive(self.zip, self.root, '18')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_archive_traversal_denied(self):
        self.make_zip({'../escape.dll': b'no'})
        with self.assertRaisesRegex(ValueError, 'Unsafe'):
            runtime.stage_archive(self.zip, self.root, '18')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_casefold_duplicates_denied(self):
        self.make_zip({'LIB/HTTP.DLL': pe64()})
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            runtime.stage_archive(self.zip, self.root, '18')

    def test_existing_parent_symlink_escape_denied(self):
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        try:
            (self.root / 'lib').symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest('Host does not grant test symlink privilege')
        self.make_zip()
        with self.assertRaisesRegex(ValueError, 'escapes'):
            runtime.stage_archive(self.zip, self.root, '18')
        self.assertEqual(list(outside.iterdir()), [])

    def test_changed_bytes_or_hash_or_major_denied(self):
        for pg, (size, sha) in runtime.PINS.items():
            self.assertEqual(len(sha), 64)
            runtime.verify_pin(pg, size, sha)
            with self.assertRaises(ValueError):
                runtime.verify_pin(pg, size + 1, sha)
            with self.assertRaises(ValueError):
                runtime.verify_pin(pg, size, '0' * 64)
        with self.assertRaises(ValueError):
            runtime.verify_pin('19', 100, '0' * 64)

    def test_non_ci_execution_denied(self):
        if sys.platform == 'win32':
            self.skipTest('Non-CI guard tested on Linux; Windows CI must qualify')
        with self.assertRaisesRegex(ValueError, 'ephemeral'):
            runtime.qualify('18')


if __name__ == '__main__':
    unittest.main()
