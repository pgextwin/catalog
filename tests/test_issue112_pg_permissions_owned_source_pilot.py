"""Offline private pg_permissions candidate packaging + adversarial tests."""
import hashlib
from io import BytesIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import issue112_pg_permissions_owned_source_pilot as pilot
from issue112_pg_permissions_source_pins import PINNED
from issue112_sql_owned_archive import canonical_zip, verify_zip

LICENSE = (b"Copyright (c) 2018-2023, CYBERTEC\n"
           b"provided that the above copyright notice and the\n"
           b"following two paragraphs appear in all copies.\n")


def fixture(root):
    pins = {}
    for name in PINNED:
        content = (LICENSE if name == "LICENSE" else
                   b"default_version = '1.4'\n" if name == "pg_permissions.control" else
                   ("-- " + name + "\n").encode())
        (root / name).write_bytes(content)
        pins[name] = hashlib.sha1(b"blob " + str(len(content)).encode() +
                                  b"\0" + content).hexdigest()
    return pins


class PgPermissionsPrivatePackageTests(unittest.TestCase):
    def test_five_major_source_owned_deterministic_and_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pins = fixture(root)
            packages = set()
            for pg in pilot.MAJORS:
                raw, receipt = pilot.build_bytes(root, pg, pins=pins, require_commit=False)
                again, _ = pilot.build_bytes(root, pg, pins=pins, require_commit=False)
                self.assertEqual(raw, again)
                packages.add(raw)
                self.assertEqual(receipt['upstreamPackageVersion'], '1.4.1')
                self.assertEqual(receipt['sqlExtensionDefaultVersion'], '1.4')
                self.assertTrue(receipt['fullUpstreamLicenseIncluded'])
                self.assertTrue(all(receipt[flag] is False for flag in pilot.FLAGS))
                with zipfile.ZipFile(BytesIO(raw)) as z:
                    self.assertEqual(len(z.namelist()), 10)
                    self.assertEqual(z.read('LICENSE'), LICENSE)
                    self.assertEqual(json.loads(z.read('SOURCE-INPUTS.json')), receipt)
            self.assertEqual(len(packages), 5)

    def test_tampered_source_extra_or_missing_sql_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pins = fixture(root)
            name = 'pg_permissions--1.0.sql'
            (root / name).write_bytes(b'-- unexpected bytes')
            with self.assertRaisesRegex(ValueError, 'pinned Git blob mismatch'):
                pilot.build_bytes(root, '18', pins=pins, require_commit=False)
            (root / name).unlink()
            with self.assertRaisesRegex(ValueError, 'unexpected or missing'):
                pilot.build_bytes(root, '18', pins=pins, require_commit=False)
            (root / name).write_bytes(b'-- unexpected bytes')
            (root / 'pg_permissions--9.9.sql').write_bytes(b'-- extra')
            with self.assertRaisesRegex(ValueError, 'unexpected or missing'):
                pilot.build_bytes(root, '18', pins=pins, require_commit=False)

    def test_signature_and_permission_flags_cannot_be_promoted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pins = fixture(root)
            raw, _ = pilot.build_bytes(root, '18', pins=pins, require_commit=False)
            with zipfile.ZipFile(BytesIO(raw)) as z:
                members = {n: z.read(n) for n in z.namelist()}
            forged = json.loads(members['SOURCE-INPUTS.json'])
            forged['downloadAuthorized'] = True
            members['SOURCE-INPUTS.json'] = json.dumps(forged).encode()
            genuine = pilot.manifest(pilot.exact_sources(root, pins, False), '18')
            expected = {**members, 'SOURCE-INPUTS.json':
                        (json.dumps(genuine, sort_keys=True,
                         separators=(',', ':')) + '\n').encode()}
            with self.assertRaisesRegex(ValueError, 'canonical exact'):
                verify_zip(canonical_zip(members), expected)

    def test_wrong_major_unsafe_paths_rights_and_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pins = fixture(root)
            with self.assertRaisesRegex(ValueError, 'unsupported PG'):
                pilot.build_bytes(root, '19', pins=pins, require_commit=False)
            fake = mock.Mock(returncode=0, stdout='f'*40)
            with mock.patch.object(pilot.subprocess, 'run', return_value=fake):
                with self.assertRaisesRegex(ValueError, 'wrong source commit'):
                    pilot.build_bytes(root, '18', pins=pins)
            with self.assertRaisesRegex(ValueError, 'unsafe source member'):
                canonical_zip({'LICENSE': LICENSE, 'SOURCE-INPUTS.json': b'x',
                               '../escape.sql': b'x'})
            (root / 'LICENSE').write_bytes(b'License removed')
            with self.assertRaisesRegex(ValueError, 'pinned Git blob mismatch'):
                pilot.build_bytes(root, '18', pins=pins, require_commit=False)

    def test_symlink_deny_and_casefold_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pins = fixture(root)
            path = root / 'pg_permissions--1.0.sql'
            path.unlink()
            try:
                path.symlink_to(root / 'LICENSE')
            except OSError:
                self.skipTest('symlinks unavailable')
            with self.assertRaisesRegex(ValueError, 'linked'):
                pilot.build_bytes(root, '18', pins=pins, require_commit=False)
            with self.assertRaisesRegex(ValueError, 'unsafe source member|casefold duplicate'):
                canonical_zip({'LICENSE': LICENSE, 'SOURCE-INPUTS.json': b'x',
                               'share/extension/pg_permissions.control': b'a',
                               'share/extension/PG_PERMISSIONS.control': b'b'})


if __name__ == '__main__':
    unittest.main()
