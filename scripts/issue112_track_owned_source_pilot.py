#!/usr/bin/env python3
"""Create a private, deterministic pgextwin-owned SQL-source pilot, NEVER a release.

The only source of installable bytes is the immutable upstream Git tree.
Cybertec originals and issuer/publisher controls are not involved.
"""
from __future__ import annotations
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import stat
import subprocess
import zipfile

SOURCE_REPO = "rjuju/pg_track_settings"
SOURCE_SHA = "36a23f3c6d684c40140da1a24b1c3ee0e707b77a"
VERSION = "2.1.2"
MAJORS = ("14", "15", "16", "17", "18")
SCHEMA = "pgextwin-issue112-track-owned-source-pilot/v1"
# Exact Git blobs observed at the immutable upstream Git tree.
BLOBS = {
    "LICENSE": "480aa8d292243ebe5c152a37fe1787bee77811ce",
    "pg_track_settings.control": "19867f8855f81f7b70b5b95c11f56308f5ff77a4",
    "pg_track_settings--1.0.0--1.0.1.sql": "219c662070112feaad0f0081949157b9380d7b5e",
    "pg_track_settings--1.0.0.sql": "76a019042a8281d656b32ee97cea601d4a1838e1",
    "pg_track_settings--1.0.1--1.1.0.sql": "6f07d80b63235f54084538b4cf59e2bdc9b9c6c1",
    "pg_track_settings--1.0.1.sql": "b71acc9c1dd37d0062a93491f620209988f91ee0",
    "pg_track_settings--1.1.0.sql": "632cd6776d4e2359ce5886af216a31ce26691b19",
    "pg_track_settings--2.0.0--2.0.1.sql": "aff152f7d687800200ca638deef412624a7ff000",
    "pg_track_settings--2.0.0.sql": "a7a9bd2d4a25a6267d9d640cc6d8e46c44ac90c7",
    "pg_track_settings--2.0.1--2.1.0.sql": "952d22c51b83f94af6bb520249d5ba02bf8cfad0",
    "pg_track_settings--2.0.1.sql": "d1647bde5e7d2882ad602dc4bc309d77862a973e",
    "pg_track_settings--2.1.0--2.1.2.sql": "b1eb89a5020db19338b6501878b8e858bc586293",
    "pg_track_settings--2.1.0.sql": "2a7919aa441483dcdf6d6fd7f7ccfd37df246a0a",
    "pg_track_settings--2.1.2.sql": "ce8eeca2c79e8cbdde1b1056547115171018c9f3",
}
FILE_MAX = 100_000
SQL_NAME = re.compile(r"pg_track_settings--[0-9.]+(?:--[0-9.]+)?\.sql\Z")

def deny_if(condition, reason):
    if condition:
        raise ValueError("SOURCE_PILOT_DENY: " + reason)

def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()

def exact_source(source, blobs=BLOBS, require_commit=True):
    root = Path(source)
    deny_if(not root.is_dir() or root.is_symlink(), "invalid source directory")
    deny_if(set(blobs) != set(BLOBS), "unexpected source member set")
    if require_commit:
        cmd = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                             text=True, capture_output=True, check=False)
        deny_if(cmd.returncode or cmd.stdout.strip() != SOURCE_SHA,
                "source checkout not the pinned upstream commit")
    files = {}
    for name, expected in sorted(blobs.items()):
        deny_if("/" in name or "\\" in name or name in (".", ".."), "unsafe source name")
        p = root / name
        deny_if(not p.exists() or not stat.S_ISREG(p.lstat().st_mode),
                "missing or linked source file: " + name)
        deny_if(p.stat().st_size > FILE_MAX or p.stat().st_size == 0,
                "invalid source size: " + name)
        data = p.read_bytes()
        deny_if(git_blob(data) != expected, "Git blob pin mismatch: " + name)
        files[name] = data
    deny_if(len(files) != 14 or len([n for n in files if SQL_NAME.fullmatch(n)]) != 12,
            "unexpected installable file count")
    deny_if(b"default_version = '2.1.2'" not in files["pg_track_settings.control"],
            "default version differs")
    deny_if(b"Copyright (c) 2015-2023, Julien Rouhaud" not in files["LICENSE"] or
            b"provided that the above copyright notice" not in files["LICENSE"],
            "copyright or notice grant missing")
    return files

def manifest(files, pg):
    return {
        "schemaVersion": SCHEMA,
        "status": "CANDIDATE_ONLY",
        "kind": "PGEXTWIN_OWNED_SOURCE_ONLY_PRIVATE_PILOT_NOT_CYBERTEC_ORIGINAL",
        "upstreamRepository": SOURCE_REPO,
        "upstreamCommit": SOURCE_SHA,
        "upstreamVersion": VERSION,
        "postgresqlMajor": pg,
        "sourceFileSha256": {
            n: hashlib.sha256(v).hexdigest() for n, v in sorted(files.items())},
        "rightsNoticeIncluded": True,
        "cybertecProducerAttestation": False,
        "independentSignatureVerified": False,
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
        "releaseAuthorized": False,
        "publisherAuthorized": False,
    }

def encode_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()

def build_bytes(source, pg, *, blobs=BLOBS, require_commit=True):
    deny_if(pg not in MAJORS, "unsupported PostgreSQL major")
    files = exact_source(source, blobs=blobs, require_commit=require_commit)
    receipt = manifest(files, pg)
    members = {"LICENSE": files["LICENSE"], "SOURCE-INPUTS.json": encode_json(receipt)}
    members.update({"share/extension/" + n: v for n, v in files.items() if n != "LICENSE"})
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9,
                         strict_timestamps=True) as archive:
        for name in sorted(members):
            zinfo = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zinfo.external_attr = 0o100644 << 16
            archive.writestr(zinfo, members[name], compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=9)
    raw = stream.getvalue()
    inspect_bytes(raw, files, pg)
    return raw, receipt

def inspect_bytes(raw, files, pg):
    deny_if(not 0 < len(raw) < 2_000_000, "archive size")
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        names = archive.namelist()
        expected = sorted(["LICENSE", "SOURCE-INPUTS.json"] +
                          ["share/extension/" + n for n in files if n != "LICENSE"])
        deny_if(names != expected or len(set(names)) != 15, "archive member allowlist")
        deny_if(archive.testzip() is not None, "ZIP CRC")
        for name in names:
            value = (encode_json(manifest(files, pg)) if name == "SOURCE-INPUTS.json" else
                     files["LICENSE"] if name == "LICENSE" else
                     files[name.removeprefix("share/extension/")])
            deny_if(archive.read(name) != value, "archive content mismatch")
        deny_if(json.loads(archive.read("SOURCE-INPUTS.json"))["publisherAuthorized"] is not False,
                "unexpected publication flag")
    return True

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pg", required=True, choices=MAJORS)
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path,
                   help="Private create-only candidate ZIP; never upload")
    args = p.parse_args()
    raw, receipt = build_bytes(args.source, args.pg)
    deny_if(not args.output.parent.is_dir() or args.output.parent.is_symlink(),
            "unsafe output directory")
    with args.output.open("xb") as f:
        f.write(raw)
    print(json.dumps({"status": receipt["status"], "postgresqlMajor": args.pg,
                      "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
                      "members": 15, "licenseMember": "LICENSE", "publicGet": "DENY",
                      "mirror": "DENY", "release": "DENY"}, sort_keys=True))

if __name__ == "__main__":
    main()
