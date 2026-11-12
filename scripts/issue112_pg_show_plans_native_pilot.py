#!/usr/bin/env python3
"""Fail-closed immutable upstream source intake for a PRIVATE Windows/MSVC pilot.

This is source inspection, not an original Cybertec ZIP, binary, or admission.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

UPSTREAM = "cybertec-postgresql/pg_show_plans"
TAG = "v2.1.8"
COMMIT = "92ecb21f8f2307a4bc7db8f01623599e75930fc2"
SQL_VERSION = "2.1"
PINS = {
    "LICENSE": "28b161b3482da3f1c3633dc3bb4f5a7866daebcc",
    "pg_show_plans.c": "60bb9f6d38709f5e399f65a9a9fa5e0c0849dbd1",
    "pg_show_plans.control": "6bb4989c0ee51189354690d769ac8c1860fa942f",
    "pg_show_plans--1.0--1.1.sql": "3c0478cd67681f8f127ca732bfbbb38501f63508",
    "pg_show_plans--1.1--2.0.sql": "72226a5e7bb2a7e92a84dd8b73f42b319c790677",
    "pg_show_plans--2.0--2.1.sql": "7e4c8a72439a6041e84f78fac94cf8e8650c0e15",
    "pg_show_plans--2.1.sql": "9fff32190bef6c758425ebf371ecb62d4b0757a6",
}
DENY = dict(
    publicGetAuthorized=False, mirrorAuthorized=False, releaseAuthorized=False,
    publisherAuthorized=False, independentlySignedAdmission=False,
    producerBinaryAttestationVerified=False,
)


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\x00" + data).hexdigest()


def verify_files(root, pins):
    root = Path(root)
    if not root.is_dir() or root.is_symlink() or not pins:
        raise ValueError("Missing, linked or empty fixed source tree")
    hashes = {}
    for name, expected in sorted(pins.items()):
        if (type(name) is not str or re.fullmatch(r"[A-Za-z0-9_.-]+", name) is None
                or "/" in name or name in (".", "..")
                or type(expected) is not str or re.fullmatch(r"[a-f0-9]{40}", expected) is None):
            raise ValueError("Unsafe source file pin")
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("Missing or linked source input: " + name)
        if not 0 < path.stat().st_size < 1_000_000:
            raise ValueError("Oversized or empty source input: " + name)
        raw = path.read_bytes()
        if git_blob(raw) != expected:
            raise ValueError("Git blob mismatch: " + name)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    return hashes


# PostgreSQL's PG_FUNCTION_INFO_V1 already declares this function, and
# PG16+ uses PGDLLEXPORT where PG14/15 does not. An earlier separate
# prototype conflicts with that declaration on MSVC (C2375). Remove only
# this redundant prototype in disposable, fully pinned source checkout.
MSVC_OLD = b"Datum pg_show_plans(PG_FUNCTION_ARGS);"
MSVC_NEW = b"/* MSVC: PG_FUNCTION_INFO_V1 supplies the exported function declaration. */"


def msvc_patch_source(raw):
    if type(raw) is not bytes or raw.count(MSVC_OLD) != 1 or MSVC_NEW in raw:
        raise ValueError("Unexpected source declarations; MSVC patch denied")
    return raw.replace(MSVC_OLD, MSVC_NEW)


def verify_source(root):
    root = Path(root)
    hashes = verify_files(root, PINS)
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True, timeout=10)
        actual = result.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Cannot authenticate upstream commit") from exc
    if actual != COMMIT:
        raise ValueError("Upstream commit differs from signed v2.1.8 tag")
    control = (root / "pg_show_plans.control").read_text(encoding="utf-8")
    if re.findall(r"(?m)^default_version\s*=\s*'([^']+)'\s*$", control) != [SQL_VERSION]:
        raise ValueError("Unexpected SQL extension version")
    source = (root / "pg_show_plans.c").read_text(encoding="utf-8")
    if "PG_MODULE_MAGIC;" not in source or "PG_FUNCTION_INFO_V1(pg_show_plans)" not in source:
        raise ValueError("Expected module magic or SQL function absent")
    return {
        "schemaVersion": "pgextwin-issue112-pg-show-plans-owned-native-private-pilot/v1",
        "status": "CANDIDATE_ONLY",
        "sourceRepository": UPSTREAM, "signedTagObserved": TAG,
        "sourceCommit": COMMIT, "upstreamReleaseVersion": "2.1.8",
        "sqlExtensionDefaultVersion": SQL_VERSION,
        "sourceFileSha256": hashes, "windowsBuildVerified": False,
        "windowsRuntimeVerified": False, "licensedFinalPackageVerified": False,
        **DENY,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--msvc-adapt", action="store_true",
                   help="Apply one bounded compile-only declaration change in disposable checkout")
    args = p.parse_args()
    report = verify_source(args.source)
    if args.msvc_adapt:
        source_path = args.source / "pg_show_plans.c"
        patched = msvc_patch_source(source_path.read_bytes())
        source_path.write_bytes(patched)
        report["msvcDisposableDeclarationPatch"] = "REMOVE_REDUNDANT_FUNCTION_PROTOTYPE_FOR_PG14_18"
        report["msvcPatchedCSourceSha256"] = hashlib.sha256(patched).hexdigest()
    print(json.dumps(report, sort_keys=True))
    print("SOURCE_PIN=PASS BINARY=NOT_YET_ACCEPTED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
