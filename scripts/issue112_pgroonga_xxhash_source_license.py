#!/usr/bin/env python3
"""Independent xxHash source-license and external-import name triage; DENY only.

An immutable upstream source LICENSE is not evidence that its terms were
shipped with the original PGroonga ZIP, nor a signed source-to-binary attestation.
"""
import argparse
import base64
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request

from issue112_pgroonga_rights_audit import PINS, audit_members, download_original, original_name
from issue112_pgroonga_pe_imports import inspect_archive
from issue112_pgroonga_dependency_rights_graph import graph

PGROONGA_COMMIT = "47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc"
WRAP_BLOB = "35cfd29d909dd6c6c60f22568bc1ce06add35d4e"
XXHASH_COMMIT = "e626a72bc2321cd320e953a0ccf1584cad60f363"
LICENSE_BLOB = "e4c5da7234eca7baad9a46f0b144e49ccad2e500"
SOURCE_SHA256 = "aae608dfe8213dfd05d909a57718ef82f30722c392344583d3f39050c7f29a80"
PATCH_SHA256 = "c7f78fc2d08ec21ff1bae928d7bdcddb42713a07d9d973a885c59ea7f8cf6bc8"
ROOT = "https://api.github.com/repos/"
OS_HINTS = frozenset(("advapi32.dll", "dbghelp.dll", "kernel32.dll",
                      "psapi.dll", "ws2_32.dll"))
VC_HINTS = frozenset(("msvcp140.dll", "vcomp140.dll", "vcruntime140.dll",
                      "vcruntime140_1.dll"))
CRT_API_HINTS = frozenset(
    f"api-ms-win-crt-{part}-l1-1-0.dll" for part in (
        "convert", "environment", "filesystem", "heap", "locale", "math",
        "runtime", "stdio", "string", "time", "utility"))
EXPECTED_EXTERNAL = OS_HINTS | VC_HINTS | CRT_API_HINTS | frozenset(
    ("liblz4.dll", "postgres.exe"))
assert len(EXPECTED_EXTERNAL) == 22
XXHASH_BINARIES = frozenset(("bin/libxxhash.dll", "bin/xxhsum.exe"))
XXHASH_AFFECTED = frozenset(XXHASH_BINARIES | {"lib/pgroonga.dll"})


def require(ok, reason):
    if not ok:
        raise ValueError("PGroonga source-license DENY: " + reason)


def unique(pairs):
    obj = {}
    for k, v in pairs:
        require(k not in obj, "duplicate GitHub JSON key")
        obj[k] = v
    return obj


def github_json(owner_repo, path):
    url = ROOT + owner_repo + "/" + path
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "pgextwin-original-license-audit/1",
        **({"Authorization": "Bearer " + os.environ["GH_TOKEN"]}
           if os.environ.get("GH_TOKEN") else {}),
    })
    with urllib.request.urlopen(req, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url,
                "unexpected GitHub REST redirect")
        payload = response.read(200001)
    require(len(payload) <= 200000, "unbounded GitHub response")
    return json.loads(payload, object_pairs_hook=unique)


def check_path_identity(metadata, expected_path, expected_blob):
    require(metadata.get("type") == "file" and
            metadata.get("path") == expected_path and
            metadata.get("sha") == expected_blob and
            0 < metadata.get("size", 0) <= 20000,
            "source commit tree path did not bind expected Git blob")


def check_tag(ref):
    require(ref.get("ref") == "refs/tags/v0.8.3" and
            ref.get("object", {}).get("type") == "commit" and
            ref["object"].get("sha") == XXHASH_COMMIT,
            "xxHash tag changed or wrong object")
    return XXHASH_COMMIT


def decode_pinned_blob(reply, expected_sha, cap):
    require(reply.get("sha") == expected_sha and
            reply.get("encoding") == "base64" and
            isinstance(reply.get("content"), str), "wrong Git blob identity")
    raw = base64.b64decode("".join(reply["content"].split()), validate=True)
    require(0 < len(raw) <= cap and
            hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") +
                         bytes([0]) + raw).hexdigest() == expected_sha,
            "Git blob content, size or SHA1 mismatch")
    return raw.decode("utf-8", errors="strict")


def check_wrap(source):
    cfg = configparser.ConfigParser(interpolation=None, strict=True)
    cfg.read_string(source)
    require(set(cfg.sections()) == {"wrap-file", "provide"}, "unexpected wrap sections")
    fields = cfg["wrap-file"]
    required = {
        "directory": "xxHash-0.8.3",
        "source_url": "https://github.com/Cyan4973/xxHash/archive/v0.8.3.tar.gz",
        "source_filename": "xxHash-0.8.3.tar.gz",
        "source_hash": SOURCE_SHA256,
        "patch_filename": "xxhash_0.8.3-2_patch.zip",
        "patch_url": "https://wrapdb.mesonbuild.com/v2/xxhash_0.8.3-2/get_patch",
        "patch_hash": PATCH_SHA256,
        "source_fallback_url": "https://github.com/mesonbuild/wrapdb/releases/download/xxhash_0.8.3-2/xxHash-0.8.3.tar.gz",
        "wrapdb_version": "0.8.3-2",
    }
    require(dict(fields) == required and dict(cfg["provide"]) == {
        "libxxhash": "xxhash_dep"}, "version/source/patch/hash changed in wrap")
    return {"declaredVersion": "0.8.3", "declaredSourceArchiveSha256": SOURCE_SHA256,
            "declaredPatchSha256": PATCH_SHA256}


def check_license(source):
    normalized = " ".join(source.split())
    require(source.startswith("xxHash Library\n") and
            "Copyright (c) 2012-2021 Yann Collet" in source and
            "BSD 2-Clause License" in source and
            "Redistributions of source code must retain the above copyright notice" in
            normalized and
            "Redistributions in binary form must reproduce the above copyright notice" in
            normalized and
            "documentation and/or other materials provided with the distribution" in
            normalized and
            "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS" in normalized,
            "upstream BSD-2-Clause text/conditions not observed")
    return {"upstreamLicense": "BSD-2-Clause (pinned source text)",
            "binaryRedistributionRequiresNotice": True,
            "upstreamLicenseSha256": hashlib.sha256(source.encode("utf-8")).hexdigest()}


def source_legal_receipts(tag, wrap, license_blob):
    check_tag(tag)
    wrap_text = decode_pinned_blob(wrap, WRAP_BLOB, 10000)
    license_text = decode_pinned_blob(license_blob, LICENSE_BLOB, 20000)
    return {
        "producerTaggedSourceCommit": PGROONGA_COMMIT,
        "producerWrapBlob": WRAP_BLOB,
        "upstreamXxhashTaggedSourceCommit": XXHASH_COMMIT,
        "upstreamXxhashLicenseBlob": LICENSE_BLOB,
        **check_wrap(wrap_text), **check_license(license_text),
        "sourceLicenseTextVerified": True,
        "releasedXxhashBinaryBoundToThisSource": False,
        "historicalMutableGroongaInputDigestVerified": False,
    }


def classify_import_name(name):
    if name in CRT_API_HINTS:
        return "WINDOWS_CRT_API_SET_NAME_ONLY"
    if name in OS_HINTS:
        return "WINDOWS_OS_DLL_NAME_ONLY"
    if name in VC_HINTS:
        return "VC_RUNTIME_DLL_NAME_ONLY"
    if name == "liblz4.dll":
        return "EDB_HOST_LZ4_NAME_ONLY_SEPARATE_SAMPLED_LOAD"
    if name == "postgres.exe":
        return "POSTGRES_SERVER_EXE_NAME_ONLY"
    return "UNCLASSIFIED_UNVERIFIED"


def review_original(pg, archive, license_receipts):
    rights = audit_members(archive, pg)
    imports = inspect_archive(archive, pg)
    joined = graph(rights, imports, strict=True)
    names = {x["name"] for x in joined["notBundledImportNames"]}
    require(joined["parsedPeMembers"] == 43 and
            joined["namedLegalDocuments"] == 25 and
            names == EXPECTED_EXTERNAL and
            not joined["ambiguousBundledImportNames"],
            "original static import inventory drift")
    require(set(joined["missingNamedNoticeAtOwnBinary"]) == XXHASH_BINARIES
            and set(joined["staticReachableMissingNamedNoticeConsumers"]) ==
            XXHASH_AFFECTED, "xxHash binary/consumer notice gap drift")
    require(all(x["sha256"] and len(x["sha256"]) == 64
                for x in joined["perBinaryGraph"]), "missing binary receipt")
    categories = sorted(
        [{"name": name, "category": classify_import_name(name),
          "actualWindowsLoaderOriginVerified": False,
          "relevantThirdPartyRightsVerified": False}
         for name in names], key=lambda x: x["name"])
    return {
        "schemaVersion": "pgextwin-pgroonga-xxhash-source-license-deny-only/v1",
        "pgMajor": pg, "version": "4.1.0",
        "originalZipSha256": PINS[pg][1],
        **license_receipts,
        "originalXxhashBinariesWithoutNamedLicense": sorted(XXHASH_BINARIES),
        "transitiveConsumersAffectedByMissingNamedLicense": sorted(XXHASH_AFFECTED),
        "externalImportNamesObserved": len(categories),
        "externalImportNameTriage": categories,
        "namedUpstreamLicensePresentInOriginalZip": False,
        "binaryRedistributionNoticeDeliveryVerified": False,
        "allThirdPartyRightsAndDependenciesVerified": False,
        "signedBuildInputToBinaryAttestationVerified": False,
        "ownerSignedAdmissionVerified": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "releaseAuthorized": False, "publisherAuthorized": False,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pg", required=True, type=int, choices=tuple(PINS))
    args = p.parse_args()
    tag = github_json("Cyan4973/xxHash", "git/ref/tags/v0.8.3")
    wrap_path = github_json(
        "pgroonga/pgroonga",
        "contents/subprojects/xxhash.wrap?ref=" + PGROONGA_COMMIT)
    check_path_identity(wrap_path, "subprojects/xxhash.wrap", WRAP_BLOB)
    license_path = github_json(
        "Cyan4973/xxHash", "contents/LICENSE?ref=" + XXHASH_COMMIT)
    check_path_identity(license_path, "LICENSE", LICENSE_BLOB)
    wrap = github_json("pgroonga/pgroonga", "git/blobs/" + WRAP_BLOB)
    license_blob = github_json("Cyan4973/xxHash", "git/blobs/" + LICENSE_BLOB)
    fixed = source_legal_receipts(tag, wrap, license_blob)
    with tempfile.TemporaryDirectory(prefix="pgroonga-xxhash-rights-") as tmp:
        archive = Path(tmp) / original_name(args.pg)
        download_original(args.pg, archive)
        report = review_original(args.pg, archive, fixed)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    print("SOURCE_LICENSE_TEXT=VERIFIED NOTICE_DELIVERY=DENY "
          "BINARY_SOURCE_BINDING=DENY 22_IMPORT_ORIGINS=UNVERIFIED "
          "SIGNED_PRODUCER=DENY OWNER=DENY PUBLIC_GET=DENY "
          "MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
