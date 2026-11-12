#!/usr/bin/env python3
"""Bounded observed OSGeo PG18 server DLL byte provenance (deny-only).

Only a sampled Windows postgres.exe module and exact original ZIP member
can be matched. EDB preinstalled dependencies, unsampled modules, rights,
dynamic loader closure and producer signatures remain explicitly unverified.
"""
import argparse
import json
import ntpath
from pathlib import Path
import re

from issue112_osgeo_pg18_live_roots import ZIP_SHA, ROOT, exact_windows_path, unique_json

SOURCE = "https://download-cache.osgeo.org/postgis/windows/pg18/" + ROOT + ".zip"
DLL = re.compile(r"[A-Za-z0-9_.+-]+[.]dll\Z", re.IGNORECASE)
HEX = re.compile(r"[0-9a-f]{64}\Z")
ROOTS = ("postgis-3.dll", "libpgrouting-4.0.dll")


def check_digest(value):
    if type(value) is not str or not HEX.fullmatch(value):
        raise ValueError("Expected exact lowercase SHA256")


def check_target(path, pgroot, filename):
    result = exact_windows_path(path)
    if ntpath.basename(result) != filename:
        raise ValueError("Untrusted target basename")
    if ntpath.dirname(result) not in (
            ntpath.join(pgroot, "bin"), ntpath.join(pgroot, "lib")):
        raise ValueError("Untrusted target parent")
    return result


def audit_loaded_bundle(data):
    if type(data) is not dict or set(data) != {
            "pgMajor", "originalZipSha256", "source", "pgRoot",
            "sampledProcessCount", "expectedServerMembers",
            "observedModules", "preservedHostDll"}:
        raise ValueError("Unexpected receipt structure or permission claim")
    if (data["pgMajor"] != "18" or data["originalZipSha256"] != ZIP_SHA
            or data["source"] != SOURCE):
        raise ValueError("Wrong immutable original source")
    if type(data["sampledProcessCount"]) is not int or not 1 <= data["sampledProcessCount"] <= 1000:
        raise ValueError("Untrusted sample count")
    pgroot = exact_windows_path(data["pgRoot"])
    expected_rows = data["expectedServerMembers"]
    observed_rows = data["observedModules"]
    if (type(expected_rows) is not list or not 2 <= len(expected_rows) <= 256
            or type(observed_rows) is not list or not 2 <= len(observed_rows) <= 512):
        raise ValueError("Invalid bounded original / sampled module set")

    expected = {}
    members = set()
    for row in expected_rows:
        if type(row) is not dict or set(row) != {"member", "sha256", "bytes"}:
            raise ValueError("Unexpected immutable member fields")
        member = row["member"]
        if type(member) is not str or not member.startswith(ROOT + "/"):
            raise ValueError("Different bundle member root")
        rel = member[len(ROOT) + 1:].split("/")
        if len(rel) != 2 or rel[0] not in ("bin", "lib") or not DLL.fullmatch(rel[1]):
            raise ValueError("Not a direct server DLL member")
        if type(row["bytes"]) is not int or not 0 < row["bytes"] <= 64 * 1024 * 1024:
            raise ValueError("Unbounded original DLL")
        check_digest(row["sha256"])
        target = ntpath.join(pgroot, rel[0], rel[1].lower())
        if member in members or target in expected:
            raise ValueError("Duplicate or ambiguous original member")
        members.add(member)
        expected[target] = {"member": member, "sha256": row["sha256"], "bytes": row["bytes"]}
    for name in ROOTS:
        if ntpath.join(pgroot, "lib", name) not in expected:
            raise ValueError("Missing original server root: " + name)

    preserved = data["preservedHostDll"]
    if type(preserved) is not dict or set(preserved) != {"name", "path", "sha256"}:
        raise ValueError("Host substitution requires explicit exact receipt")
    if preserved["name"] != "libcurl.dll":
        raise ValueError("Only known EDB libcurl substitution accepted")
    pre_path = check_target(preserved["path"], pgroot, "libcurl.dll")
    if pre_path != ntpath.join(pgroot, "bin", "libcurl.dll"):
        raise ValueError("EDB curl must be in PostgreSQL bin")
    check_digest(preserved["sha256"])

    observed = {}
    for row in observed_rows:
        if type(row) is not dict or set(row) != {"name", "path", "sha256"}:
            raise ValueError("Untrusted observed module fields")
        name = row["name"]
        if type(name) is not str or not DLL.fullmatch(name) or name != name.lower():
            raise ValueError("Unsafe observed DLL name")
        path = check_target(row["path"], pgroot, name)
        check_digest(row["sha256"])
        if path in observed:
            raise ValueError("Duplicate live DLL path")
        observed[path] = row["sha256"]

    rows = []
    original_match = 0
    preserved_edb = 0
    unverified = 0
    host_other = 0
    for path, digest in sorted(observed.items()):
        if path == pre_path and digest != preserved["sha256"]:
            raise ValueError("Observed EDB libcurl changed from the pre-staging SHA256")
        origin = expected.get(path)
        if origin and origin["sha256"] == digest:
            status = "EXACT_ORIGINAL_MEMBER_BYTE_MATCH"
            original_match += 1
        elif path == pre_path and digest == preserved["sha256"]:
            status = "PRESERVED_EDB_HOST_NOT_ORIGINAL"
            preserved_edb += 1
        elif origin:
            status = "UNVERIFIED_ORIGINAL_PATH_HASH_MISMATCH"
            unverified += 1
        else:
            status = "PG_HOST_OR_UNMAPPED_NOT_ORIGINAL"
            host_other += 1
        if path in (ntpath.join(pgroot, "lib", n) for n in ROOTS) and status != "EXACT_ORIGINAL_MEMBER_BYTE_MATCH":
            raise ValueError("Root DLL did not match original bytes")
        rows.append({
            "name": ntpath.basename(path),
            "path": path,
            "observedSha256": digest,
            "originalMember": origin["member"] if origin else None,
            "originClass": status,
        })
    if any(ntpath.join(pgroot, "lib", n) not in observed for n in ROOTS):
        raise ValueError("Missing sampled PostGIS/pgRouting server root")
    return {
        "schemaVersion": "pgextwin-osgeo-pg18-sampled-server-member-origins-deny-only/v1",
        "pgMajor": "18",
        "originalZipSha256": ZIP_SHA,
        "sampledProcessCount": data["sampledProcessCount"],
        "originalDirectServerDllCount": len(expected),
        "sampledPgBinLibDllCount": len(observed),
        "sampledExactOriginalMemberMatches": original_match,
        "sampledPreservedEdbHostDlls": preserved_edb,
        "sampledUnverifiedOriginalPathMismatches": unverified,
        "sampledOtherPgHostDllsNotInOriginal": host_other,
        "originalMembersNotObserved": len(set(expected).difference(observed)),
        "sampledModules": rows,
        "originalRootByteMatch": True,
        "allPossibleDynamicLoadsObserved": False,
        "transitiveDependencyClosureVerified": False,
        "allComponentRightsAndNoticesVerified": False,
        "producerSourceToZipSigned": False,
        "ownerSignedAdmission": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "releaseAuthorized": False, "publisherAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    path = parser.parse_args().receipt
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 1048576:
        raise ValueError("Missing or unbounded origin receipt")
    data = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_json)
    result = audit_loaded_bundle(data)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    print("OSGEO_PG18_SAMPLED_MEMBER_ORIGINS=OBSERVED "
          "DYNAMIC_CLOSURE=UNVERIFIED RIGHTS=UNVERIFIED PRODUCER_SIGNED=NO "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
