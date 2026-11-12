#!/usr/bin/env python3
"""PRIVATE pg_show_plans exact-ZIP SPDX file inventory and PE imports; no publication.

An SPDX file inventory is not a vulnerability clearance, full dependency SBOM,
source-to-binary attestation, independent signature or Publisher authorization.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from issue112_osgeo_dependency_inventory import static_imports
from issue112_pg_show_plans_private_package import (
    MAJORS, TAG, archive_members, inspect_bytes, sha,
    verified_derived_source, verified_dll,
)

def spdx_inventory(zip_raw, expected, major, created=None):
    """Inventory *only* verified original ZIP members, with actual file hashes."""
    if major not in MAJORS:
        raise ValueError("Unsupported PG major")
    inspect_bytes(zip_raw, expected)
    digest = sha(zip_raw)
    files = []
    relations = [{
        "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Package",
    }]
    sha1s = []
    for i, (name, data) in enumerate(sorted(expected.items()), 1):
        fid = "SPDXRef-File-%d" % i
        s1 = hashlib.sha1(data).hexdigest()
        sha1s.append(s1)
        files.append({
            "SPDXID": fid, "fileName": "./" + name,
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": s1},
                {"algorithm": "SHA256", "checksumValue": sha(data)},
            ],
            "fileTypes": ["BINARY" if name.endswith(".dll") else "TEXT"],
            "licenseConcluded": "NOASSERTION",
            "licenseInfoInFiles": ["NOASSERTION"],
            "copyrightText": "NOASSERTION",
        })
        relations.append({
            "spdxElementId": "SPDXRef-Package", "relationshipType": "CONTAINS",
            "relatedSpdxElement": fid,
        })
    if created is None:
        created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if (type(created) is not str or len(created) != 20 or
            created[-1] != "Z"):
        raise ValueError("Invalid SPDX UTC creation time")
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "pgextwin-private-pg_show_plans-%s-pg%d" % (TAG, major),
        "documentNamespace":
            "https://spdx.org/spdxdocs/pgextwin-issue112-private-%s" % digest,
        "creationInfo": {"creators": [
            "Tool: pgextwin-issue112-pg-show-plans-private-sbom/1"
        ], "created": created},
        "documentComment":
            "Runner-local file inventory; no signature, vulnerability or "
            "license/dependency closure claim and no public GET authorization.",
        "packages": [{
            "SPDXID": "SPDXRef-Package", "name": "pg_show_plans-private-pg%d" % major,
            "versionInfo": TAG, "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "packageVerificationCode": {"packageVerificationCodeValue":
                hashlib.sha1("".join(sorted(sha1s)).encode("ascii")).hexdigest()},
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "sourceInfo": "Pinned upstream source; source/dll details in SOURCE-INPUTS.json",
            "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
        }],
        "files": files, "relationships": relations,
    }

def imported_dlls(dll):
    """Strict bounded PE import enumeration, NOT loader/dependency closure."""
    names, delayed = static_imports(dll)
    if not names:
        raise ValueError("No static DLL imports in supposedly linked extension")
    return {
        "staticImports": sorted(set(names)),
        "delayImports": sorted(set(delayed)),
        "dynamicDependenciesVerified": False,
        "targetWindowsImportResolutionVerified": False,
        "thirdPartyNoticesVerified": False,
        "vulnerabilityClearanceVerified": False,
        "producerAttestationVerified": False,
        "independentSignatureVerified": False,
        "publicGetAuthorized": False,
        "mirrorAuthorized": False,
        "releaseAuthorized": False,
        "publisherAuthorized": False,
    }

def audit(source, dll_path, major, zip_path):
    files = verified_derived_source(source)
    dll = verified_dll(dll_path)
    expected = archive_members(files, dll, major)
    package = Path(zip_path)
    if not package.is_file() or package.is_symlink():
        raise ValueError("Missing or symlinked private ZIP")
    raw = package.read_bytes()
    doc = spdx_inventory(raw, expected, major)
    return doc, imported_dlls(dll), sha(raw)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--dll", type=Path, required=True)
    p.add_argument("--major", type=int, choices=MAJORS, required=True)
    p.add_argument("--zip", type=Path, required=True)
    p.add_argument("--sbom", type=Path, required=True)
    args = p.parse_args()
    doc, imports, digest = audit(args.source, args.dll, args.major, args.zip)
    out = args.sbom
    if not out.parent.is_dir() or out.parent.is_symlink() or out.exists() or out.is_symlink():
        raise ValueError("Unsafe or existing runner-local SBOM destination")
    with out.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(doc, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    print(json.dumps({
        "privateZipSha256": digest, "pgMajor": args.major,
        "spdxFileCount": len(doc["files"]), "peImportObservation": imports,
        "runnerLocalSbom": True, "uploaded": False,
    }, sort_keys=True))
    print("PRIVATE_SPDX_FILE_INVENTORY=PASS PE_STATIC_IMPORTS=OBSERVED "
          "FULL_DEPENDENCY_CLOSURE=DENY VULN_CLEARANCE=DENY "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")

if __name__ == "__main__":
    main()
