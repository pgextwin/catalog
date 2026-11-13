#!/usr/bin/env python3
"""Source-pinned private pg_permissions 1.4.1 SQL ZIPs; NEVER Cybertec originals.

Nonpublishing evidence only. Normal protected source/Windows/signing/Publisher
acceptance must be completed independently before any public download.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from issue112_pg_permissions_source_pins import PINNED, NEW_COMMIT, blob_sha, read_pinned
from issue112_sql_owned_archive import canonical_zip, verify_zip

SOURCE_REPO = "cybertec-postgresql/pg_permissions"
MAJORS = ("14", "15", "16", "17", "18")
SCHEMA = "pgextwin-issue112-pg-permissions-owned-source-private/v1"
FLAGS = ("cybertecOriginalZip", "cybertecProducerAttestationVerified",
         "independentSourceSignatureVerified", "windowsRuntimeFromThisZipVerified",
         "downloadAuthorized", "mirrorAuthorized", "releaseAuthorized",
         "publisherAuthorized")


def require(condition, reason):
    if not condition:
        raise ValueError("PG_PERMISSIONS_SOURCE_DENY: " + reason)


def exact_sources(root, pins=PINNED, require_commit=True):
    root = Path(root)
    require(type(pins) is dict and set(pins) == set(PINNED),
            "unexpected source names")
    # Parent helper rejects extras, missing files, symlinks and altered Git blobs.
    read_pinned(root, pins)
    if require_commit:
        result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=15, check=False)
        require(result.returncode == 0 and result.stdout.strip() == NEW_COMMIT,
                "wrong source commit")
        # Worktree-wide porcelain is not a source-byte proof on Windows: the
        # upstream repository contains unrelated files normalized differently
        # by the checkout. Compare every *used* path to the immutable Git tree
        # instead; read_pinned also verifies the corresponding worktree bytes.
        tree = subprocess.run(["git", "-C", str(root), "ls-tree", "HEAD", "--",
                               *sorted(pins)], capture_output=True, text=True,
                              timeout=15, check=False)
        require(tree.returncode == 0, "cannot authenticate pinned source tree")
        actual = {}
        for line in tree.stdout.splitlines():
            try:
                spec, name = line.split("\\t", 1)
                mode, kind, oid = spec.split()
            except ValueError as exc:
                raise ValueError("PG_PERMISSIONS_SOURCE_DENY: malformed Git tree") from exc
            require(mode == "100644" and kind == "blob" and name not in actual,
                    "unexpected upstream Git tree member")
            actual[name] = oid
        require(actual == pins, "upstream Git tree differs from exact source pins")
    sources = {name: (root / name).read_bytes() for name in sorted(pins)}
    require(all(blob_sha(data) == pins[name] for name, data in sources.items()),
            "source files changed between verification and packaging")
    notice = sources["LICENSE"]
    require(b"Copyright (c) 2018-2023, CYBERTEC" in notice and
            b"provided that the above copyright notice" in notice and
            b"following two paragraphs appear in all copies" in notice,
            "upstream notice is not reproduced")
    require(b"default_version = '1.4'" in sources["pg_permissions.control"],
            "SQL extension version changed")
    require(len(sources) == 9, "unexpected SQL/control/license count")
    return sources


def manifest(files, pg):
    return {
        "schemaVersion": SCHEMA,
        "status": "CANDIDATE_ONLY",
        "kind": "PGEXTWIN_OWNED_SQL_SOURCE_NOT_CYBERTEC_ORIGINAL",
        "upstreamRepository": SOURCE_REPO,
        "upstreamCommit": NEW_COMMIT,
        "upstreamPackageVersion": "1.4.1",
        "sqlExtensionDefaultVersion": "1.4",
        "postgresqlMajor": pg,
        "sourceFileSha256": {name: hashlib.sha256(raw).hexdigest()
                             for name, raw in sorted(files.items())},
        "fullUpstreamLicenseIncluded": True,
        **{flag: False for flag in FLAGS},
    }


def build_bytes(root, pg, *, pins=PINNED, require_commit=True):
    require(pg in MAJORS, "unsupported PG major")
    files = exact_sources(root, pins=pins, require_commit=require_commit)
    receipt = manifest(files, pg)
    members = {"LICENSE": files["LICENSE"],
               "SOURCE-INPUTS.json": (json.dumps(receipt, sort_keys=True,
                separators=(",", ":")) + "\n").encode("utf-8")}
    members.update({"share/extension/" + name: data
                    for name, data in files.items() if name != "LICENSE"})
    raw = canonical_zip(members)
    verify_zip(raw, members)
    require(all(receipt[flag] is False for flag in FLAGS),
            "private-only receipt modified")
    return raw, receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--pg", choices=MAJORS, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    raw, receipt = build_bytes(args.source, args.pg)
    require(args.output.parent.is_dir() and not args.output.parent.is_symlink(),
            "invalid private output parent")
    with args.output.open("xb") as file:
        file.write(raw)
    print(json.dumps({"status": receipt["status"], "source": SOURCE_REPO,
                      "upstreamPackageVersion": "1.4.1", "sqlDefaultVersion": "1.4",
                      "pgMajor": args.pg, "sha256": hashlib.sha256(raw).hexdigest(),
                      "bytes": len(raw), "members": 10,
                      "publicGet": "DENY", "publisher": "DENY"}, sort_keys=True))


if __name__ == "__main__":
    main()
