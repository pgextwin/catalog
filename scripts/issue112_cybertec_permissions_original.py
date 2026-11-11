#!/usr/bin/env python3
"""Private original-byte Cybertec pg_permissions candidate pilot, never an admission."""
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import stat
import urllib.request
import zipfile

from issue112_pg_permissions_source_pins import PINNED, read_pinned

# This is the provider's REL_1_4 package, NOT a 1.4.1 package. Upstream
# REL_1_4_1 happened to preserve the installable Git blobs unchanged.
BASE = 'https://repository.cybertec.at/windows/public/'
MAJORS = ('14', '15', '16', '17', '18')
PROVIDER_LABEL = 'REL_1_4-1'
UPSTREAM_COMMIT = 'f622556f511231521b5e30e662a93e838c6a2b2f'
LATEST_UPSTREAM_COMMIT = '3360447e0668fed2b9db6a0ae1d086533781f9bd'
MAX_ZIP = 3_000_000
MAX_FILES = 128
MAX_EXPANDED = 8_000_000
SQL = re.compile(r'pg_permissions--[0-9A-Za-z.\\-]+\\.sql\\Z')
REQUIRED_SQL = frozenset((
    'pg_permissions--1.0.sql', 'pg_permissions--1.0--1.1.sql',
    'pg_permissions--1.1.sql', 'pg_permissions--1.1--1.2.sql',
    'pg_permissions--1.2.sql', 'pg_permissions--1.3.sql',
    'pg_permissions--1.3--1.4.sql'))
REQUIRED = REQUIRED_SQL | {'pg_permissions.control'}
DENIALS = dict(publicGetAuthorized=False, mirrorAuthorized=False,
               publisherAuthorized=False, releaseAuthorized=False,
               independentlySignedAdmission=False,
               producerProvenanceVerified=False,
               rightsNoticeClosureVerified=False)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError('Redirected Cybertec original refused')


def original_url(pg):
    if pg not in MAJORS:
        raise ValueError('Unsupported PostgreSQL major')
    return f'{BASE}{pg}/extension/pg_permissions-{pg}-public-{PROVIDER_LABEL}.zip'


def review_zip(raw, pg, source=None):
    if pg not in MAJORS or type(raw) is not bytes or not 0 < len(raw) <= MAX_ZIP:
        raise ValueError('Original ZIP missing, oversized or unsupported major')
    found = {}
    members = []
    notices = []
    seen = set()
    expanded = 0
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        entries = archive.infolist()
        if not 2 <= len(entries) <= MAX_FILES:
            raise ValueError('ZIP entry count out of bounds')
        for entry in entries:
            name = entry.filename
            if (not name or name.startswith('/') or '\\' in name or ':' in name or
                    '\x00' in name or name.casefold() in seen or
                    any(p in ('', '.', '..') for p in name.rstrip('/').split('/')) or
                    stat.S_IFMT(entry.external_attr >> 16) == stat.S_IFLNK):
                raise ValueError('Unsafe or duplicate ZIP member')
            seen.add(name.casefold())
            if entry.file_size > MAX_EXPANDED or entry.file_size > 300 * max(1, entry.compress_size):
                raise ValueError('ZIP member expansion limit')
            expanded += entry.file_size
            if expanded > MAX_EXPANDED:
                raise ValueError('ZIP cumulative expansion limit')
            if entry.is_dir():
                continue
            members.append(name)
            leaf = name.rsplit('/', 1)[-1]
            if leaf.casefold() in ('license', 'license.txt', 'license.md', 'copying',
                                   'notice', 'notice.txt', 'notice.md'):
                notices.append(name)
            if leaf == 'pg_permissions.control' or SQL.fullmatch(leaf):
                if leaf in found:
                    raise ValueError('Duplicate installable member basename')
                found[leaf] = archive.read(entry)
        if archive.testzip() is not None:
            raise ValueError('ZIP CRC check failed')
    if set(found) != REQUIRED:
        raise ValueError('Missing, added or unrecognized installable SQL/control member')
    if not re.search(rb"(?m)^default_version\\s*=\\s*'1\\.4'\\s*$", found['pg_permissions.control']):
        raise ValueError('Unrecognized SQL extension default version')
    matched, different, missing = [], [], []
    if source is not None:
        root = Path(source)
        if not root.is_dir() or root.is_symlink():
            raise ValueError('Missing or linked immutable upstream source checkout')
        for leaf, data in sorted(found.items()):
            src = root / leaf
            if src.is_symlink():
                raise ValueError('Linked pinned source')
            if not src.is_file():
                missing.append(leaf)
            elif src.read_bytes() == data:
                matched.append(leaf)
            else:
                different.append(leaf)
    result = {
        'schemaVersion': 'pgextwin-issue112-cybertec-pg-permissions-original/v1',
        'status': 'CANDIDATE_ONLY',
        'provider': 'CYBERTEC_PGEE_PUBLIC_ABI_UNVERIFIED',
        'postgresqlMajor': pg,
        'providerOriginalPackageLabel': 'REL_1_4',
        'providerArchivePackagingRevision': '1',
        'upstreamReleaseLatestObserved': '1.4.1',
        'sqlExtensionDefaultVersion': '1.4',
        'comparisonUpstreamCommit': UPSTREAM_COMMIT,
        'latestSourceInstallablesIdenticalCommit': LATEST_UPSTREAM_COMMIT,
        'originalUrl': original_url(pg),
        'originalSizeBytes': len(raw),
        'originalSha256': hashlib.sha256(raw).hexdigest(),
        'zipCrc': 'PASS', 'zipMemberCount': len(entries),
        'unpackedBytes': expanded, 'zipMembers': sorted(members),
        'installableSqlAndControl': sorted(found),
        'installableMemberSha256': {k: hashlib.sha256(v).hexdigest() for k, v in sorted(found.items())},
        'packagedLicenseNoticeMembers': sorted(notices),
        'sourceExactByteMatches': matched,
        'sourceByteDiffers': different,
        'sourceNotPresent': missing,
        'completeSourceSqlControlMatch': source is not None and not different and not missing,
        **DENIALS,
    }
    return result, found


def review_original(pg, source=None, opener=None):
    url = original_url(pg)
    if opener is None:
        opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, headers={
        'Accept': 'application/zip, application/octet-stream',
        'User-Agent': 'pgextwin-private-original-byte-audit/1'})
    with opener.open(request, timeout=45) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError('Original origin status or redirect mismatch')
        media = response.headers.get('Content-Type', '').split(';')[0].lower().strip()
        if media not in ('application/zip', 'application/octet-stream',
                         'application/x-zip-compressed'):
            raise ValueError('Unexpected ZIP media type')
        length = response.headers.get('Content-Length')
        if length is not None and (not length.isdecimal() or not 0 < int(length) <= MAX_ZIP):
            raise ValueError('Original declared length out of bounds')
        raw = response.read(MAX_ZIP + 1)
    if length is not None and len(raw) != int(length):
        raise ValueError('Original response truncated')
    return review_zip(raw, pg, source)


def stage_verified(found, dest):
    """Stage only original installable ZIP bytes on an isolated runner; never upload."""
    dest = Path(dest)
    if dest.exists() or dest.is_symlink() or not dest.parent.is_dir():
        raise ValueError('Unsafe or existing staging destination')
    dest.mkdir(mode=0o700)
    try:
        for leaf in sorted(REQUIRED):
            with (dest / leaf).open('xb') as handle:
                handle.write(found[leaf])
    except BaseException:
        import shutil
        shutil.rmtree(dest)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pg', choices=MAJORS, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--stage', type=Path, help='Private ephemeral directory, must not exist')
    args = parser.parse_args()
    # The prior protected source-pin verifier checks all 7 SQL, control and LICENSE.
    read_pinned(args.source, PINNED)
    result, found = review_original(args.pg, args.source)
    if not result['completeSourceSqlControlMatch']:
        raise ValueError('Original ZIP differs from pinned upstream installable source')
    if args.stage is not None:
        stage_verified(found, args.stage)
    print(json.dumps(result, sort_keys=True))
    print('ORIGINAL_BYTES=OBSERVED SOURCE_SQL_CONTROL_MATCH=YES PACKAGE_LABEL=REL_1_4 '
          'SQL_VERSION=1.4 LATEST_UPSTREAM_RELEASE=1.4.1 '
          'PRODUCER_SIGNATURE=UNVERIFIED RIGHTS_NOTICE=UNVERIFIED '
          'PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY')


if __name__ == '__main__':
    main()
