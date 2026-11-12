#!/usr/bin/env python3
"""Rehash original PGroonga 4.1.0 Actions outer artifacts -> Release ZIP bytes.

DENY-only: an original run artifact to Release ZIP byte match is not a
signed historical source-input attestation, rights clearance or owner grant.
No file is downloaded, uploaded, signed or published by this tool.
"""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import zipfile

from issue112_pgroonga_producer_boundary import (
    ARTIFACTS, COMMIT, RUNS, WINDOWS_JOBS, require,
)
from issue112_pgroonga_rights_audit import PINS, VERSION

assert {int(k) for k in ARTIFACTS} == set(PINS) == {
    int(k) for k in WINDOWS_JOBS
}

DENY = {
    "signedHistoricalGroongaInputToBinaryAttestationVerified": False,
    "allThirdPartyRightsAndDependenciesVerified": False,
    "sourceSpecificOwnerSignedGetAdmissionVerified": False,
    "publicGetAuthorized": False,
    "mirrorAuthorized": False,
    "releaseAuthorized": False,
    "publisherAuthorized": False,
}


def sha256_file_bounded(path, exact_bytes):
    require(path.is_file() and not path.is_symlink(),
            "missing, nonregular or symlink Actions archive")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            require(total <= exact_bytes, "oversized Actions archive")
            digest.update(chunk)
    require(total == exact_bytes, "truncated Actions archive")
    return digest.hexdigest()


def verify_original_outer(pg, outer):
    """Verify pinned, previously authenticated outer digest AND embedded ZIP.

    This is *not* an online proof of the current upstream metadata. Metadata
    identity and original Run/attempt/actor are checked by the existing
    issue112_pgroonga_producer_boundary auditor, which provides these pins.
    """
    require(type(pg) is int and pg in PINS, "unsupported PostgreSQL major")
    outer = Path(outer)
    aid, outer_bytes, outer_sha = ARTIFACTS[str(pg)]
    inner_bytes, inner_sha = PINS[pg]
    found_sha = sha256_file_bounded(outer, outer_bytes)
    require(found_sha == outer_sha, "original Actions artifact SHA256 mismatch")
    expected_member = f"pgroonga-{VERSION}-postgresql-{pg}-x64.zip"
    try:
        with zipfile.ZipFile(outer, "r") as archive:
            entries = archive.infolist()
            require(len(entries) == 1 and
                    entries[0].filename == expected_member,
                    "wrong/multiple original Actions member paths")
            entry = entries[0]
            mode = (entry.external_attr >> 16) & 0o170000
            require(mode in (0, stat.S_IFREG) and not entry.is_dir() and
                    not (entry.flag_bits & 1) and
                    entry.file_size == inner_bytes,
                    "unsafe, encrypted or wrong-size original inner ZIP")
            digest = hashlib.sha256()
            length = 0
            with archive.open(entry, "r") as stream:
                while chunk := stream.read(1024 * 1024):
                    length += len(chunk)
                    require(length <= inner_bytes, "oversized extracted ZIP")
                    digest.update(chunk)
            require(length == inner_bytes and digest.hexdigest() == inner_sha,
                    "original inner ZIP differs from pinned official Release")
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise ValueError("PGroonga producer-chain DENY: invalid outer ZIP") from exc
    return {
        "pgMajor": pg,
        "taggedPgroongaSourceCommit": COMMIT,
        "originalWindowsRunId": RUNS["windows"][0],
        "originalWindowsRunAttempt": RUNS["windows"][1],
        "originalWindowsJobId": WINDOWS_JOBS[str(pg)],
        "originalActionsArtifactId": aid,
        "originalActionsOuterBytes": outer_bytes,
        "verifiedActionsOuterSha256": found_sha,
        "originalActionsInnerName": expected_member,
        "originalInnerBytes": length,
        "verifiedInnerSha256MatchesReleasePin": digest.hexdigest(),
        "actionsArtifactToReleaseByteIdentityVerified": True,
        "signedSourceInputToBinaryAttestationVerified": False,
        "historicalGroongaLatestZipDigestKnown": False,
    }


def report(rows):
    require(len(rows) == len({x["pgMajor"] for x in rows}),
            "duplicate PostgreSQL major in original artifact report")
    return {
        "schemaVersion": "pgextwin-pgroonga-actions-inner-release-bytes-deny-only/v1",
        "originalWindowsRunId": RUNS["windows"][0],
        "sourceCommit": COMMIT,
        "scope": "ORIGINAL_ACTIONS_OUTER_TO_RELEASE_INNER_BYTE_IDENTITY_ONLY",
        "verified": sorted(rows, key=lambda r: r["pgMajor"]),
        **DENY,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--all-dir", type=Path,
                       help="directory with pgroonga-upstream-original-pg{major}.zip for all PG14-18")
    group.add_argument("--artifact", type=Path, help="one original Actions outer ZIP")
    p.add_argument("--pg", type=int, choices=tuple(PINS),
                   help="required only with --artifact")
    args = p.parse_args()
    if args.all_dir is not None:
        require(args.pg is None and args.all_dir.is_dir(),
                "invalid complete-cohort directory arguments")
        rows = [
            verify_original_outer(pg, args.all_dir / f"pgroonga-upstream-original-pg{pg}.zip")
            for pg in sorted(PINS)
        ]
    else:
        require(args.pg in PINS, "--artifact requires exact --pg")
        rows = [verify_original_outer(args.pg, args.artifact)]
    print(json.dumps(report(rows), sort_keys=True, separators=(",", ":")))
    print("ACTIONS_TO_RELEASE_INNER_BYTES=VERIFIED SIGNED_PRODUCER_INPUT=DENY "
          "RIGHTS=DENY OWNER=DENY PUBLIC_GET=DENY MIRROR=DENY "
          "RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
