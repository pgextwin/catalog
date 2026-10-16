"""Issue #112 historical original-archive compatibility regression (synthetic, never signed)."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import distribution_historical_p1_bridge as h
from distribution_manifest_v1 import Denied


def pack(members, *, fmt=tarfile.PAX_FORMAT):
    """members: (name, bytes, pax_fields, type)"""
    f = io.BytesIO()
    with tarfile.open(fileobj=f, mode='w:gz', format=fmt) as tar:
        for name, data, pax, type_ in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1792152033.123456
            if type_ == 'link':
                info.type, info.linkname, info.size = tarfile.SYMTYPE, 'elsewhere', 0
            elif type_ == 'hardlink':
                info.type, info.linkname, info.size = tarfile.LNKTYPE, 'elsewhere', 0
            elif type_ == 'dir':
                info.type, info.size = tarfile.DIRTYPE, 0
            if pax:
                info.pax_headers = pax
            tar.addfile(info, io.BytesIO(data) if info.isfile() else None)
    return f.getvalue()


def file_(name='safe/file.txt', data=b'data', pax=None, kind='file'):
    return (name, data, pax, kind)


def manifest(items, *, schema='pgextwin-issue112-resume6-manifest/v1'):
    return {'schema': schema,
            'repoId': h.PIN['repoId'], 'releaseId': h.PIN['releaseId'],
            'publicationAuthorized': False, 'distributionAuthorized': False,
            'signatureOrTrustedTimestamp': False,
            'files': [{'path': name, 'size': len(data),
                       'sha256': hashlib.sha256(data).hexdigest()}
                      for name, data in items.items()]}


class HistoricArchiveOriginalCompatibility(unittest.TestCase):
    def deny(self, func, *args, **kwargs):
        with self.assertRaises((Denied, ValueError, TypeError, KeyError)):
            func(*args, **kwargs)

    def test_standard_concrete_path_bytes_success_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'real.tar.gz'
            p.write_bytes(b'original')
            self.assertEqual(h.pinned_bytes(p, 8, hashlib.sha256(b'original').hexdigest()), b'original')
            self.deny(h.pinned_bytes, p, 9, hashlib.sha256(b'original').hexdigest())
            self.deny(h.pinned_bytes, p, 8, '0' * 64)
            link = Path(directory) / 'link'
            link.symlink_to(p)
            self.deny(h.pinned_bytes, link, 8, hashlib.sha256(b'original').hexdigest())

    def test_pax_numeric_mtime_normal_original(self):
        result = h.safe_tar(pack([file_()]))
        self.assertEqual(result, {'safe/file.txt': b'data'})

    def test_pax_only_exact_long_pg14_path(self):
        name = (h.PG14_PREFIX + 'snapshot/assets/' +
                'pg_bigm-v1.2-20250903-pg14-windows-x64.vulnerabilities.json')
        self.assertGreater(len(name), 100)
        self.assertEqual(h.safe_tar(pack([file_(name)]), allow_pg14_cache=True)[name], b'data')
        self.deny(h.safe_tar, pack([file_(name)]))

    def test_historical_sigstore_cache_path_only_in_old_archive(self):
        name = (h.PG14_CACHE_PREFIX + 'root/tuf-repo.github.com/'
                'targets/trusted_root.json')
        h.historical_tar_path(name, allow_pg14_cache=True)
        self.deny(h.historical_tar_path, name)
        self.deny(h.historical_tar_path, name.replace('.sigstore/', '../'))
        self.deny(h.historical_tar_path, name.replace('root/', '../', 1), allow_pg14_cache=True)
        self.deny(h.historical_tar_path, name.replace('root/', 'folder//', 1), allow_pg14_cache=True)
        self.deny(h.historical_tar_path, name.replace('/root/', '/root/./', 1), allow_pg14_cache=True)

    def test_pax_foreign_key_rejected(self):
        self.deny(h.safe_tar, pack([file_(pax={'comment': 'not original'})]))
        self.deny(h.safe_tar, pack([file_(pax={'mtime': '-100.0'})]))
        self.deny(h.safe_tar, pack([file_(pax={'mtime': '1000000000000000000.0'})]))
        self.deny(h.safe_tar, pack([file_(pax={'mtime': 'NaN'})]))

    def test_pax_path_override_rejected(self):
        self.deny(h.safe_tar, pack([file_('safe/file.txt', pax={'path':'safe/other.txt'})]))
        self.deny(h.safe_tar, pack([file_('safe/file.txt', pax={'path':'../evil'})]))
        name = h.PG14_PREFIX + 'snapshot/assets/' + 'x'*70
        self.deny(h.safe_tar, pack([file_(name, pax={'path':'../evil'})]), allow_pg14_cache=True)

    def test_tar_duplicate_and_casefold_rejected(self):
        self.deny(h.safe_tar, pack([file_('safe/file.txt'), file_('safe/file.txt')]))
        self.deny(h.safe_tar, pack([file_('safe/a.txt'), file_('safe/A.TXT')]))

    def test_tar_traversal_symlink_hardlink_special_rejected(self):
        for name in ('../evil', '/root/data', 'bad/../../x', 'bad/./x',
                     'C:/windows', 'bad\\file', 'bad//file', 'bad/CON', './foo'):
            with self.subTest(name=name):
                self.deny(h.safe_tar, pack([file_(name)]))
        for kind in ('link', 'hardlink'):
            with self.subTest(kind=kind):
                self.deny(h.safe_tar, pack([file_(kind, kind=kind)]))

    def test_tar_safe_directory_is_not_payload(self):
        data=pack([file_('original/',kind='dir'),file_('original/a',b'good')])
        self.assertEqual(h.safe_tar(data), {'original/a':b'good'})

    def test_tar_total_entries_and_size(self):
        self.deny(h.safe_tar, pack([file_(f'f{i}', b'x') for i in range(h.MAX_ENTRIES + 1)]))
        self.deny(h.safe_tar, pack([file_('one', b'x' * (h.MAX_MEMBER + 1))]))
        self.deny(h.safe_tar, b'not archive')

    def test_self_manifest_only_one_exact_extra(self):
        items = {f'resume6/a{i}': bytes([i]) for i in range(31)}
        obj = manifest(items)
        external = json.dumps(obj).encode()
        digest = hashlib.sha256(external).hexdigest()
        entries = dict(items, **{h.SELF_MANIFEST: external})
        self.assertEqual(h.check_self_manifest(entries, original=external,
                          original_sha=digest, count=31), items)
        self.deny(h.check_self_manifest, items, original=external, original_sha=digest, count=31)
        self.deny(h.check_self_manifest, dict(entries, rogue=b'bad'),
                  original=external, original_sha=digest, count=31)
        self.deny(h.check_self_manifest, dict(entries, **{h.SELF_MANIFEST: b'fake'}),
                  original=external, original_sha=digest, count=31)
        h.validate_manifest(items, obj)

    def test_nested_59_file_manifest_exact_members(self):
        items = {f'audit/item{i}': bytes([i]) for i in range(59)}
        obj = {'files': manifest(items)['files']}
        h.validate_nested_prior_manifest(items, obj)
        self.deny(h.validate_nested_prior_manifest, dict(items, extra=b'x'), obj)
        mutant = copy.deepcopy(obj)
        mutant['files'][1]['path'] = mutant['files'][0]['path']
        self.deny(h.validate_nested_prior_manifest, items, mutant)
        mutant = copy.deepcopy(obj)
        mutant['files'][0]['sha256'] = '0'*64
        self.deny(h.validate_nested_prior_manifest, items, mutant)

    def test_pg14_69_file_membership_and_forged_root(self):
        items = {h.PG14_PREFIX + f'snapshot/test{i}.txt': bytes([i]) for i in range(69)}
        obj = {'schema':'pgextwin-issue112-reaudit-sha256-manifest/v1',
               'releaseId':h.PIN['releaseId'], 'catalogSnapshotCommit':h.PIN['catalog'],
               'publicationAuthorized':False,
               'files':[{'path':k[len(h.PG14_PREFIX):], 'size':len(v),
                         'sha256':hashlib.sha256(v).hexdigest()} for k,v in items.items()]}
        data = json.dumps(obj).encode()
        members = dict(items, **{h.PG14_PREFIX + h.SELF_MANIFEST:data})
        self.assertEqual(h.validate_pg14_manifest(members), items)
        self.deny(h.validate_pg14_manifest, dict(members, rogue=b'evil'))
        for key, value in [('releaseId',0), ('publicationAuthorized',True),
                           ('catalogSnapshotCommit','0'*40)]:
            mutant=copy.deepcopy(obj);mutant[key]=value
            self.deny(h.validate_pg14_manifest,
                      dict(items, **{h.PG14_PREFIX + h.SELF_MANIFEST:json.dumps(mutant).encode()}))

    def test_payload_lookup_only_pinned_three_locations(self):
        fake={f'p{i}':{'origin':'NEW_GET_THIS_RUN','size':1,
                        'digest':'sha256:'+'a'*64} for i in range(16)}
        self.deny(h.identify_asset_bytes, {}, {}, {}, fake)

    def test_old_receipt_identity_replay_wrong_run_signer_root_rejected(self):
        original={**h.RECEIPT_FIELDS,
                  'verifiedBundleSha256':{'https://slsa.dev/provenance/v1':'a'*64,
                                            'https://spdx.dev/Document/v2.3':'b'*64}}
        h.validate_receipt_pins(original)
        for key, bad in [('profile','historical-plpgsql_check-pg14/1'),
                         ('assetId',0),('runId',38128142145),('attempt',2),
                         ('originalRootSha256','0'*64),('signerSha','0'*40),
                         ('upstreamCommit','0'*40),('publicationAuthorized',True),
                         ('distributionAuthorized',True)]:
            with self.subTest(key=key):
                obj=dict(original);obj[key]=bad
                self.deny(h.validate_receipt_pins,obj)

    def test_official_gh_wrong_binary_denied(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'gh';p.write_bytes(b'fake gh')
            with patch.object(h.shutil,'which',return_value=str(p)):
                self.deny(h.verify_official_gh)

    def test_gate_does_not_start_crypto_when_archive_missing(self):
        with tempfile.TemporaryDirectory() as d:
            invalid=Path(d)/'json';invalid.write_text('{}')
            with patch.object(h, 'real_pg14_audit', side_effect=AssertionError('premature gh')) as crypto:
                self.deny(h.gate,*([invalid]*7))
                crypto.assert_not_called()

    def test_no_unintended_publish_or_p2_gate(self):
        s=(Path(__file__).resolve().parents[1]/'scripts'/'distribution_historical_p1_bridge.py').read_text()
        for literal in ('"formalP1RowsAccepted": 1', '"historicalSourceAccepted": 0',
                        '"publicationAuthorized": False', '"distributionAuthorized": False',
                        '"p2": "NO-GO"'):
            self.assertIn(literal,s)
        self.assertNotIn('38128142145',s)


if __name__ == '__main__':
    unittest.main()
