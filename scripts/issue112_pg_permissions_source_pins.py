#!/usr/bin/env python3
"""Offline, fail-closed source-byte equivalence for pg_permissions 1.4 -> 1.4.1.

Both arguments must be independent local source checkouts. This tool does no
network access and cannot authorize Cybertec original ZIPs or any public GET.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

OLD_COMMIT = "f622556f511231521b5e30e662a93e838c6a2b2f"
NEW_COMMIT = "3360447e0668fed2b9db6a0ae1d086533781f9bd"
OLD_TAG = "REL_1_4"
NEW_TAG = "REL_1_4_1"
# Independently read from authenticated GitHub Git tree GETs at both exact commits.
# Each of these nine blobs was identical in both upstream source trees.
PINNED = {
    "LICENSE": "1fd282a61d03946e180a0b82a7c82d553e175db8",
    "pg_permissions--1.0--1.1.sql": "ecacee96ce0dc1c13cb35bf3aafb31f67a8486e6",
    "pg_permissions--1.0.sql": "555465bd0c1853b69f8c0d3f953528b0c8535dfb",
    "pg_permissions--1.1--1.2.sql": "2a70e2f76419483816c436fadfea8dbf3f3f5a94",
    "pg_permissions--1.1.sql": "e8cef904e8c12957708697fbdf38f9a5fa8d8e3a",
    "pg_permissions--1.2.sql": "f6b43975bf7b90c9be2a38d3f7c8d4d5f8908c6f",
    "pg_permissions--1.3--1.4.sql": "5700c17d30c84d1b284e1a48fe33d6d92e8a5336",
    "pg_permissions--1.3.sql": "2ca444b8dc619b1a08530b71ed7855771d266231",
    "pg_permissions.control": "18ec7b614454c98b3c33b1d8e7af84167fb6e624",
}
MAX_FILE = 2_000_000
SQL_NAME = re.compile(r"pg_permissions--[0-9A-Za-z.\-]+\.sql\Z")
DEFAULT_VERSION = re.compile(rb"(?m)^default_version\s*=\s*'1\.4'\s*$")


def require(ok, reason):
    if not ok:
        raise ValueError("CANDIDATE_ONLY audit DENY: " + reason)


def blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def read_pinned(root, pins):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "missing or symlinked source tree")
    require(all(type(k) is str and k in ("LICENSE", "pg_permissions.control")
                or (type(k) is str and SQL_NAME.fullmatch(k)) for k in pins),
            "unsafe pinned member name")
    found = {p.name for p in root.iterdir()
             if p.name in ("LICENSE", "pg_permissions.control")
             or SQL_NAME.fullmatch(p.name)}
    require(found == set(pins), "unexpected or missing installable/notice file")
    result = {}
    for name, expected in sorted(pins.items()):
        require(type(expected) is str and re.fullmatch(r"[0-9a-f]{40}", expected),
                "invalid expected Git blob ID")
        path = root / name
        require(path.is_file() and not path.is_symlink(), "missing or linked file " + name)
        require(0 < path.stat().st_size <= MAX_FILE, "unbounded file " + name)
        data = path.read_bytes()
        actual = blob_sha(data)
        require(actual == expected, "pinned Git blob mismatch " + name)
        if name == "pg_permissions.control":
            require(DEFAULT_VERSION.search(data) is not None,
                    "extension default_version is not 1.4")
            require(b"1.4.1" not in data,
                    "package version confused with SQL extension version")
        result[name] = actual
    return result


def audit(old_root, new_root, pins=PINNED):
    # A caller may supply a synthetic pin map in offline tests, but the CLI
    # always uses the immutable PINNED map above.
    old = read_pinned(old_root, pins)
    new = read_pinned(new_root, pins)
    require(old == new, "installable content differs")
    return {
        "schemaVersion": "pgextwin-issue112-pg-permissions-source-only/v1",
        "status": "CANDIDATE_ONLY",
        "upstreamPackageVersion": "1.4.1",
        "sqlExtensionDefaultVersion": "1.4",
        "oldTag": OLD_TAG,
        "oldCommit": OLD_COMMIT,
        "newTag": NEW_TAG,
        "newCommit": NEW_COMMIT,
        "pinnedSourceMemberGitBlobs": new,
        "pinnedSourceLicenseAndSqlControlIdentical": True,
        "originalCybertecZipVerified": False,
        "producerProvenanceVerified": False,
        "originalZipLicenseNoticeVerified": False,
        "publicGetAuthorized": False,
        "mirrorAuthorized": False,
        "releaseAuthorized": False,
        "publisherAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--new", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.old, args.new), sort_keys=True))
    print("SOURCE_INSTALLABLE_BLOBS=IDENTICAL PROVIDER_ORIGINAL=UNVERIFIED "
          "NOTICE=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
