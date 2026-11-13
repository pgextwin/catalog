#!/usr/bin/env python3
"""Nonpublishing independent vendor Sigstore check for pglogical 2.4.8 original ZIPs.

Accepts ONLY original-byte-pinned release objects from the prior independent
Windows acceptance. Success proves the GitHub Actions signer assertion, NOT
source-to-binary reproducibility, license/NOTICE, PE closure or public GET.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from issue112_pglogical_original_windows import (
    PINS, REPO, TAG_COMMIT, fetch_original, require, verify_metadata,
)

RUN_ID = "33683623757"
SIGNER = REPO + "/.github/workflows/release.yml"
PREDICATE = "https://slsa.dev/provenance/v1"


def verified_statement(proof, name, sha):
    require(type(proof) is list and len(proof) == 1 and
            type(proof[0]) is dict, "ambiguous Sigstore verification results")
    result = proof[0].get("verificationResult")
    require(type(result) is dict, "missing verified GitHub provenance")
    statement = result.get("statement")
    require(type(statement) is dict and
            statement.get("predicateType") == PREDICATE,
            "unexpected attested predicate")
    subjects = statement.get("subject")
    require(type(subjects) is list and len(subjects) == 1 and
            type(subjects[0]) is dict and
            subjects[0].get("name") == name and
            subjects[0].get("digest") == {"sha256": sha},
            "verified subject not equal to original ZIP pin")
    predicate = statement.get("predicate")
    require(type(predicate) is dict, "missing provenance predicate")
    invocation = (predicate.get("runDetails") or {}).get("metadata", {}).get("invocationId", "")
    require(type(invocation) is str and
            invocation.startswith("https://github.com/" + REPO + "/actions/runs/" + RUN_ID),
            "provider-run invocation does not match original signed release run")


def audit(major):
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("GITHUB_EVENT_NAME") == "pull_request" and
            os.environ.get("GITHUB_REPOSITORY") == "pgextwin/catalog" and
            os.environ.get("RUNNER_OS") == "Linux" and
            os.environ.get("GH_TOKEN") and os.environ.get("RUNNER_TEMP"),
            "Sigstore verification must run in original PR-only read-only CI")
    asset_id, length, sha = PINS[major]
    url = verify_metadata(major, asset_id, length, sha)
    data = fetch_original(url, length, sha)
    filename = "pglogical-2.4.8-pg" + str(major) + "-w1-x64.zip"
    # Exact original bytes remain in ephemeral runner-local storage only.
    with tempfile.TemporaryDirectory(prefix="issue112-pglogical-sigstore-",
                                     dir=os.environ["RUNNER_TEMP"]) as temp:
        path = Path(temp) / filename
        with path.open("xb") as stream:
            stream.write(data)
        command = [
            "gh", "attestation", "verify", str(path),
            "--repo", REPO, "--signer-workflow", SIGNER,
            "--source-digest", TAG_COMMIT, "--source-ref", "refs/heads/main",
            "--predicate-type", PREDICATE, "--format", "json",
        ]
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=180, check=False)
        require(result.returncode == 0 and 0 < len(result.stdout) < 4_000_000,
                "Sigstore signature, certificate, identity, transparency or origin check failed")
        try:
            proof = json.loads(result.stdout)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Malformed GitHub Sigstore verification output") from exc
        verified_statement(proof, filename, sha)
    print(f"ORIGINAL_SHA256=PASS PG={major} ASSET={asset_id} SHA256={sha}")
    print(f"VENDOR_SIGSTORE=PASS SIGNER={SIGNER} SOURCE={TAG_COMMIT} RUN={RUN_ID}")
    print("CANDIDATE_ONLY=YES REPRODUCIBLE_BUILD=UNVERIFIED RIGHTS=UNVERIFIED "
          "PE_DEPENDENCIES=UNVERIFIED GET=DENY MIRROR=DENY RELEASE=DENY")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg", type=int, required=True, choices=sorted(PINS))
    args = parser.parse_args()
    try:
        audit(args.pg)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("PGLOGICAL_VENDOR_SIGSTORE_DENY:", str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
