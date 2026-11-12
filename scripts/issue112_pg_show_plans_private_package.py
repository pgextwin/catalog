#!/usr/bin/env python3
"""Create/verify an exact pg_show_plans private Windows ZIP; NEVER publish it."""
import argparse
from io import BytesIO
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import zipfile

from issue112_pg_show_plans_native_pilot import (COMMIT, PINS, SQL_VERSION, TAG,
                                                  git_blob, msvc_patch_source,
                                                  verify_files)

MAJORS = (14, 15, 16, 17, 18)
SCHEMA = 'pgextwin-issue112-pg-show-plans-private-msvc-package/v1'
DENIALS = {'publicGetAuthorized': False, 'mirrorAuthorized': False,
           'releaseAuthorized': False, 'publisherAuthorized': False,
           'independentSignatureVerified': False, 'runtimeVerified': False}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verified_derived_source(source):
    root = Path(source)
    verify_files(root, {n: v for n, v in PINS.items() if n != 'pg_show_plans.c'})
    cfile = root / 'pg_show_plans.c'
    if not cfile.is_file() or cfile.is_symlink():
        raise ValueError('Missing or linked compiled C source')
    head = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                          capture_output=True, check=True, timeout=10).stdout.decode().strip()
    if head != COMMIT:
        raise ValueError('Wrong original upstream commit')
    pristine = subprocess.run(['git', '-C', str(root), 'show',
                              COMMIT + ':pg_show_plans.c'],
                             capture_output=True, check=True, timeout=10).stdout
    if git_blob(pristine) != PINS['pg_show_plans.c']:
        raise ValueError('Original C git blob pin mismatch')
    if cfile.read_bytes() != msvc_patch_source(pristine):
        raise ValueError('Unapproved compiled C derivation')
    return {name: (root / name).read_bytes() for name in PINS}


def verified_dll(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or not 1024 <= path.stat().st_size <= 5_000_000:
        raise ValueError('Missing, linked or implausible DLL')
    raw = path.read_bytes()
    if raw[:2] != b'MZ' or len(raw) < 0x40:
        raise ValueError('Not Windows PE')
    offset = struct.unpack_from('<I', raw, 0x3c)[0]
    if offset + 6 > len(raw) or raw[offset:offset + 4] != b'PE\0\0' or struct.unpack_from('<H', raw, offset + 4)[0] != 0x8664:
        raise ValueError('Not AMD64 Windows PE')
    return raw


def archive_members(files, dll, major):
    if major not in MAJORS or set(files) != set(PINS):
        raise ValueError('Unsupported PG major or source inventory')
    rights = files['LICENSE']
    manifest = {'schemaVersion': SCHEMA, 'status': 'CANDIDATE_ONLY',
                'kind': 'PGEXTWIN_OWNED_PRIVATE_MSVC_NOT_CYBERTEC_BINARY',
                'sourceRepository': 'cybertec-postgresql/pg_show_plans',
                'sourceCommit': COMMIT, 'upstreamRelease': TAG,
                'sqlExtensionVersion': SQL_VERSION, 'postgresqlMajor': major,
                'sourceSha256': {n: sha(v) for n, v in sorted(files.items())},
                'licenseSha256': sha(rights), 'windowsDllSha256': sha(dll),
                **DENIALS}
    members = {'LICENSE': rights, 'SOURCE-INPUTS.json':
               (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode(),
               'lib/pg_show_plans.dll': dll}
    for name, raw in files.items():
        if name not in ('LICENSE', 'pg_show_plans.c'):
            members['share/extension/' + name] = raw
    return members


def create_bytes(members):
    stream = BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, members[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return stream.getvalue()


def inspect_bytes(raw, expected):
    if not 1024 < len(raw) < 8_000_000:
        raise ValueError('Unexpected ZIP size')
    with zipfile.ZipFile(BytesIO(raw), 'r') as archive:
        names = archive.namelist()
        if names != sorted(expected) or len(names) != len(set(names)):
            raise ValueError('ZIP member allowlist mismatch')
        for info in archive.infolist():
            if (info.is_dir() or (info.external_attr >> 16) != 0o100644 or
                    info.date_time != (1980, 1, 1, 0, 0, 0) or
                    info.file_size != len(expected[info.filename]) or
                    info.file_size > 5_000_000 or
                    archive.read(info) != expected[info.filename]):
                raise ValueError('ZIP archive member mismatch: ' + info.filename)
        if archive.testzip() is not None:
            raise ValueError('ZIP CRC mismatch')
    if raw != create_bytes(expected):
        raise ValueError('Noncanonical private ZIP bytes')
    return True


def stage_bytes(raw, expected, stage):
    root = Path(stage)
    if root.exists() or root.is_symlink():
        raise ValueError('Refuse to replace existing stage')
    inspect_bytes(raw, expected)
    root.mkdir()
    for name, data in sorted(expected.items()):
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('xb') as output:
            output.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--dll', type=Path, required=True)
    parser.add_argument('--major', type=int, choices=MAJORS, required=True)
    parser.add_argument('--zip', type=Path, required=True)
    parser.add_argument('--mode', choices=('create', 'verify-and-stage'), required=True)
    parser.add_argument('--stage', type=Path)
    args = parser.parse_args()
    files = verified_derived_source(args.source)
    dll = verified_dll(args.dll)
    expected = archive_members(files, dll, args.major)
    if args.mode == 'create':
        if args.stage is not None or not args.zip.parent.is_dir() or args.zip.parent.is_symlink():
            raise ValueError('Unsafe create destination')
        raw = create_bytes(expected)
        inspect_bytes(raw, expected)
        with args.zip.open('xb') as output:
            output.write(raw)
    else:
        if args.stage is None or not args.zip.is_file() or args.zip.is_symlink():
            raise ValueError('Missing private ZIP or stage')
        raw = args.zip.read_bytes()
        stage_bytes(raw, expected, args.stage)
    print('PRIVATE_PG_SHOW_PLANS_PG%d_ZIP=PASS BYTES=%d SHA256=%s LICENSE=EXACT PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY' %
          (args.major, len(raw), sha(raw)))


if __name__ == '__main__':
    main()
