#!/usr/bin/env python3
"""Private pg_permissions SQL-only SPDX file inventory; never admission.

Builds from the exact immutable upstream Git tree using the existing verified
private packager. Neither this unsigned SPDX file nor its ZIP is published.
"""
import argparse
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import zipfile

from issue112_pg_permissions_owned_source_pilot import (
    MAJORS, FLAGS, SCHEMA, build_bytes,
)
from issue112_pg_permissions_source_pins import PINNED, NEW_COMMIT
from issue112_sql_owned_archive import verify_zip

NAMES = frozenset({"LICENSE", "SOURCE-INPUTS.json"} |
                  {"share/extension/" + n for n in PINNED if n != "LICENSE"})
RECEIPT_KIND = "PGEXTWIN_OWNED_SQL_SOURCE_NOT_CYBERTEC_ORIGINAL"


def require(ok, reason):
    if not ok:
        raise ValueError("PG_PERMISSIONS_PRIVATE_SBOM_DENY: " + reason)


def unique_pairs(pairs):
    output = {}
    for key, value in pairs:
        require(key not in output, "duplicate source receipt key")
        output[key] = value
    return output


def spdx_inventory(raw, members, pg, created="2026-11-13T00:00:00Z"):
    """Inventory *verified canonical* ZIP bytes, never merely a proposed file list."""
    require(pg in MAJORS and type(members) is dict and set(members) == NAMES,
            "wrong PG major or unexpected source archive members")
    verify_zip(raw, members)
    try:
        receipt = json.loads(members["SOURCE-INPUTS.json"],
                             object_pairs_hook=unique_pairs)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ValueError("PG_PERMISSIONS_PRIVATE_SBOM_DENY: invalid source receipt") from exc
    require(type(receipt) is dict and
            receipt.get("schemaVersion") == SCHEMA and
            receipt.get("status") == "CANDIDATE_ONLY" and
            receipt.get("kind") == RECEIPT_KIND and
            receipt.get("upstreamRepository") == "cybertec-postgresql/pg_permissions" and
            receipt.get("upstreamCommit") == NEW_COMMIT and
            receipt.get("upstreamPackageVersion") == "1.4.1" and
            receipt.get("sqlExtensionDefaultVersion") == "1.4" and
            receipt.get("postgresqlMajor") == pg and
            receipt.get("fullUpstreamLicenseIncluded") is True and
            all(receipt.get(flag) is False for flag in FLAGS),
            "wrong source identity or permission-bearing manifest")
    source_hashes = receipt.get("sourceFileSha256")
    require(type(source_hashes) is dict and set(source_hashes) == set(PINNED),
            "incomplete or expanded source hash ledger")
    for name in PINNED:
        member = "LICENSE" if name == "LICENSE" else "share/extension/" + name
        require(source_hashes[name] == hashlib.sha256(members[member]).hexdigest(),
                "source input hash does not match original ZIP member")
    require(type(created) is str and
            re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", created) is not None,
            "invalid UTC SPDX timestamp")

    sha = lambda data: hashlib.sha256(data).hexdigest()
    sha1 = lambda data: hashlib.sha1(data).hexdigest()
    zhash = sha(raw)
    files, sha1s = [], []
    relations = [{
        "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Package",
    }]
    for index, name in enumerate(sorted(members), 1):
        data = members[name]
        file_id = "SPDXRef-File-%02d" % index
        sha1s.append(sha1(data))
        files.append({
            "SPDXID": file_id, "fileName": "./" + name,
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": sha1(data)},
                {"algorithm": "SHA256", "checksumValue": sha(data)},
            ],
            "fileTypes": ["TEXT"],
            "licenseConcluded": "NOASSERTION",
            "licenseInfoInFiles": ["NOASSERTION"],
            "copyrightText": "NOASSERTION",
        })
        relations.append({
            "spdxElementId": "SPDXRef-Package",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": file_id,
        })
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "pgextwin-private-pg_permissions-1.4.1-pg" + pg,
        "documentNamespace":
            "https://spdx.org/spdxdocs/pgextwin-issue112-private-" + zhash,
        "creationInfo": {
            "creators": ["Tool: pgextwin-issue112-sql-owned-spdx/1"],
            "created": created,
        },
        "documentComment":
            "Runner-local file-byte inventory only. Source-owned private ZIP, "
            "NOT Cybertec original. No signed producer provenance, independent "
            "admission, license/dependency closure, public GET or publication.",
        "packages": [{
            "SPDXID": "SPDXRef-Package",
            "name": "pg_permissions-private-pg" + pg,
            "versionInfo": "1.4.1",
            "downloadLocation": "NOASSERTION", "filesAnalyzed": True,
            "sourceInfo": "Exact pinned source commit " + NEW_COMMIT,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256", "checksumValue": zhash}],
            "packageVerificationCode": {"packageVerificationCodeValue":
                sha1("".join(sorted(sha1s)).encode("ascii"))},
        }],
        "files": files, "relationships": relations,
    }


def audit(source, pg, zip_path):
    expected, _ = build_bytes(source, pg)
    zip_path = Path(zip_path)
    require(zip_path.is_file() and not zip_path.is_symlink(),
            "missing or linked private ZIP")
    require(zip_path.stat().st_size == len(expected), "private ZIP byte length changed")
    actual = zip_path.read_bytes()
    require(actual == expected, "private ZIP differs from exact source-owned bytes")
    with zipfile.ZipFile(BytesIO(actual)) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    report = spdx_inventory(actual, members, pg,
                            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    return report, hashlib.sha256(actual).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--pg", choices=MAJORS, required=True)
    p.add_argument("--zip", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    doc, digest = audit(args.source, args.pg, args.zip)
    dest = args.output
    require(dest.parent.is_dir() and not dest.parent.is_symlink() and
            not dest.exists() and not dest.is_symlink(),
            "SBOM must be created only in an existing private directory")
    with dest.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(doc, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    print("PG_PERMISSIONS_PRIVATE_SPDX=PASS PG=" + args.pg +
          " FILES=" + str(len(doc["files"])) + " ZIP_SHA256=" + digest +
          " UPLOAD=NO PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
