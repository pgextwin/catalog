"""Adversarial offline tests of the private pg_show_plans MSVC ZIP contract."""
import hashlib
from io import BytesIO
import json
import sys
import tempfile
import unittest
from pathlib import Path
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from issue112_pg_show_plans_private_package import (
    MAJORS, DENIALS, archive_members, create_bytes, inspect_bytes, stage_bytes)
from issue112_pg_show_plans_native_pilot import PINS


class PrivatePackageTests(unittest.TestCase):
    def setUp(self):
        self.files = {name: ('immutable-' + name).encode() for name in PINS}
        self.dll = b'MZ' + b'x' * 2000
        self.members = archive_members(self.files, self.dll, 18)
        self.raw = create_bytes(self.members)

    def test_exact_members_rights_and_version_separation(self):
        self.assertTrue(inspect_bytes(self.raw, self.members))
        with zipfile.ZipFile(BytesIO(self.raw)) as archive:
            manifest = json.loads(archive.read('SOURCE-INPUTS.json'))
            self.assertEqual(manifest['upstreamRelease'], 'v2.1.8')
            self.assertEqual(manifest['sqlExtensionVersion'], '2.1')
            self.assertEqual(manifest['postgresqlMajor'], 18)
            self.assertEqual(manifest['licenseSha256'], hashlib.sha256(self.files['LICENSE']).hexdigest())
            self.assertEqual(manifest['windowsDllSha256'], hashlib.sha256(self.dll).hexdigest())
            self.assertTrue(all(manifest[k] is False for k in DENIALS))
            self.assertEqual(len(archive.namelist()), 8)

    def test_each_major_is_distinct_and_bad_major_denied(self):
        self.assertEqual(MAJORS, (14, 15, 16, 17, 18))
        self.assertEqual(len({hashlib.sha256(create_bytes(archive_members(self.files, self.dll, pg))).hexdigest()
                              for pg in MAJORS}), 5)
        with self.assertRaises(ValueError):
            archive_members(self.files, self.dll, 19)

    def test_archive_poison_missing_dll_and_forged_rights_denied(self):
        for poison in ('LICENSE', 'lib/pg_show_plans.dll', 'SOURCE-INPUTS.json'):
            changed = dict(self.members)
            changed[poison] = b'poisoned'
            with self.assertRaises(ValueError):
                inspect_bytes(create_bytes(changed), self.members)
        changed = dict(self.members)
        changed['unlisted.txt'] = b'poison'
        with self.assertRaisesRegex(ValueError, 'allowlist'):
            inspect_bytes(create_bytes(changed), self.members)
        changed = dict(self.members)
        del changed['lib/pg_show_plans.dll']
        with self.assertRaisesRegex(ValueError, 'allowlist'):
            inspect_bytes(create_bytes(changed), self.members)

    def test_stage_uses_exact_checked_archive_create_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / 'stage'
            stage_bytes(self.raw, self.members, stage)
            self.assertEqual((stage / 'lib/pg_show_plans.dll').read_bytes(), self.dll)
            self.assertEqual((stage / 'LICENSE').read_bytes(), self.files['LICENSE'])
            with self.assertRaisesRegex(ValueError, 'existing stage'):
                stage_bytes(self.raw, self.members, stage)

    def test_symlink_or_nonregular_zip_member_denied(self):
        stream = BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            for name in sorted(self.members):
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.external_attr = (0o120777 if name == 'LICENSE' else 0o100644) << 16
                archive.writestr(info, self.members[name])
        with self.assertRaisesRegex(ValueError, 'member mismatch'):
            inspect_bytes(stream.getvalue(), self.members)


if __name__ == '__main__':
    unittest.main()
