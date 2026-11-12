#!/usr/bin/env python3
"""Strict, offline join for OSGeo PG18 sampled Windows server DLL origins.

This is an observation only: it cannot prove dynamic loader closure, rights,
producer signatures or any public direct-provider download permission.
"""
import argparse
import json
import ntpath
from pathlib import Path
import re

ZIP_SHA = "fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40"
ROOT = "postgis-bundle-pg18-3.7.0x64"
NAMES = ("postgis-3.dll", "libpgrouting-4.0.dll")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")


def unique_json(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate receipt JSON key: " + key)
        value[key] = item
    return value


def exact_windows_path(path):
    if type(path) is not str or not path or "\x00" in path:
        raise ValueError("Invalid Windows module path")
    if not ntpath.isabs(path) or path.startswith("\\\\") or ".." in path.replace("/", "\\").split("\\"):
        raise ValueError("Untrusted Windows module path")
    return ntpath.normcase(ntpath.normpath(path))


def join_origins(data):
    if type(data) is not dict or data.get("pgMajor") != "18" or data.get("originalZipSha256") != ZIP_SHA:
        raise ValueError("Exact PG18 original identity required")
    if data.get("source") != "https://download-cache.osgeo.org/postgis/windows/pg18/" + ROOT + ".zip":
        raise ValueError("Wrong original source")
    if type(data.get("sampledProcessCount")) is not int or data["sampledProcessCount"] < 1:
        raise ValueError("No target postgres processes sampled")
    pgroot = exact_windows_path(data.get("pgRoot"))
    expected = data.get("expectedRoots")
    observed = data.get("observedModules")
    if type(expected) is not list or len(expected) != len(NAMES) or type(observed) is not list:
        raise ValueError("Incomplete roots or modules")
    pins = {}
    for entry in expected:
        if type(entry) is not dict or set(entry) != {"name", "member", "sha256"}:
            raise ValueError("Unexpected root pin fields")
        name = entry["name"]
        if name not in NAMES or name in pins or entry["member"] != ROOT + "/lib/" + name:
            raise ValueError("Missing/duplicate/ambiguous original member")
        if type(entry["sha256"]) is not str or not HEX64.fullmatch(entry["sha256"]):
            raise ValueError("Invalid original member digest")
        pins[name] = entry["sha256"]
    if set(pins) != set(NAMES):
        raise ValueError("Unpinned server root")
    modules = {}
    for entry in observed:
        if type(entry) is not dict or set(entry) != {"name", "path", "sha256", "authenticodeStatus"}:
            raise ValueError("Unexpected module fields")
        path = exact_windows_path(entry["path"])
        if ntpath.basename(path) != entry["name"].lower():
            raise ValueError("Module basename mismatch")
        if type(entry["sha256"]) is not str or not HEX64.fullmatch(entry["sha256"]):
            raise ValueError("Missing loaded module digest")
        if type(entry["authenticodeStatus"]) is not str or not entry["authenticodeStatus"]:
            raise ValueError("Missing Authenticode observation")
        if path in modules:
            raise ValueError("Duplicate sampled module path")
        modules[path] = entry
    roots = []
    for name in NAMES:
        target = ntpath.normcase(ntpath.join(pgroot, "lib", name))
        matches = [row for p, row in modules.items() if ntpath.basename(p) == name]
        if len(matches) != 1 or exact_windows_path(matches[0]["path"]) != target:
            raise ValueError("Missing or wrong-origin live server DLL: " + name)
        if matches[0]["sha256"] != pins[name]:
            raise ValueError("Live server DLL differs from exact original member: " + name)
        roots.append({"name": name, "observedPath": matches[0]["path"],
                      "originalMemberSha256": pins[name],
                      "liveByteMatch": True,
                      "authenticodeStatusObservedNotTrusted": matches[0]["authenticodeStatus"]})
    return {
        "schemaVersion": "pgextwin-osgeo-pg18-live-server-roots-nonpublishing/v1",
        "pgMajor": "18", "originalZipSha256": ZIP_SHA,
        "sampledProcessCount": data["sampledProcessCount"],
        "rootDlls": roots, "allTwoServerRootOriginsObserved": True,
        "allBundledDependenciesResolved": False,
        "dynamicLoadClosureVerified": False,
        "componentRightsAndNoticesVerified": False,
        "producerSignedProvenanceVerified": False,
        "independentOwnerAdmissionVerified": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "releaseAuthorized": False, "publisherAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    result = join_origins(json.loads(args.receipt.read_text(encoding="utf-8-sig"),
                                     object_pairs_hook=unique_json))
    print(json.dumps(result, sort_keys=True))
    print("OSGEO_PG18_LIVE_ROOTS=OBSERVED ROOTS=2 DEPENDENCY_CLOSURE=UNVERIFIED "
          "RIGHTS=UNVERIFIED PRODUCER=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY "
          "RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
