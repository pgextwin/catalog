#!/usr/bin/env python3
"""Private Windows CLI candidate byte receipt. Not a signature/provenance verifier."""
import argparse
import hashlib
import json
import pathlib
import re
import sys

FIELDS = {"schema", "name", "version", "sourceCommit", "sdkObserved",
          "runId", "sha256", "bytes", "signatureVerified",
          "provenanceVerified", "publishAuthorized", "distributionAuthorized"}


def deny(message):
    raise ValueError(message)


def inspect_binary(path):
    p = pathlib.Path(path)
    if p.name != "pgextwin.exe" or p.is_symlink() or not p.is_file():
        deny("candidate must be a real pgextwin.exe file")
    size = p.stat().st_size
    if not 1_000_000 <= size <= 150_000_000:
        deny("candidate size outside 1-150 MB bounds")
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return size, h.hexdigest()


def parse_receipt(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                deny("duplicate JSON key")
            result[key] = value
        return result
    record = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(record, dict) or set(record) != FIELDS:
        deny("receipt shape mismatch")
    return record


def check(record, size, digest, source, run_id):
    if (record["schema"] != "pgextwin-cli-r6-candidate/v1"
            or record["name"] != "pgextwin.exe"
            or record["version"] != "0.2.0"
            or record["sourceCommit"] != source
            or record["runId"] != run_id
            or not isinstance(record["sdkObserved"], str)
            or record["sdkObserved"] != "10.0.402"
            or not isinstance(record["bytes"], int)
            or isinstance(record["bytes"], bool)
            or record["bytes"] != size
            or not isinstance(record["sha256"], str)
            or record["sha256"] != digest):
        deny("candidate identity/hash mismatch")
    for key in ("signatureVerified", "provenanceVerified",
                "publishAuthorized", "distributionAuthorized"):
        if record[key] is not False:
            deny("unsupported trust or publication claim")


def main():
    a = argparse.ArgumentParser()
    a.add_argument("mode", choices=("emit", "verify"))
    a.add_argument("--binary", required=True)
    a.add_argument("--receipt", required=True)
    a.add_argument("--source", required=True)
    a.add_argument("--run-id", required=True)
    a.add_argument("--sdk")
    args = a.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.source) or not re.fullmatch(r"[0-9]+", args.run_id):
        deny("invalid source/run identity")
    size, digest = inspect_binary(args.binary)
    receipt = pathlib.Path(args.receipt)
    if receipt.is_symlink():
        deny("receipt symlink forbidden")
    if args.mode == "emit":
        if receipt.exists() or not args.sdk:
            deny("receipt collision or SDK missing")
        data = dict(schema="pgextwin-cli-r6-candidate/v1", name="pgextwin.exe",
                    version="0.2.0", sourceCommit=args.source,
                    sdkObserved=args.sdk, runId=args.run_id,
                    sha256=digest, bytes=size, signatureVerified=False,
                    provenanceVerified=False, publishAuthorized=False,
                    distributionAuthorized=False)
        check(data, size, digest, args.source, args.run_id)
        receipt.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n",
                           encoding="utf-8")
    else:
        data = parse_receipt(receipt.read_text(encoding="utf-8"))
        check(data, size, digest, args.source, args.run_id)
    print("CLI_R6_PRIVATE_BYTES=PASS SHA256=" + digest + " PUBLISH=DENY")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print("DENY: " + str(exc), file=sys.stderr)
        sys.exit(2)
