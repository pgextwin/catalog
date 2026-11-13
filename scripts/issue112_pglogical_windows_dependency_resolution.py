#!/usr/bin/env python3
"""Issue #112: candidate-only PG14-18 PE dependency resolution against pinned EDB.

Inventory only. This does not establish the Windows loader's actual search
order, forwarded/dynamic imports, WinSxS closure, component rights or GET
authorization. No provider ZIP or dependency is uploaded or redistributed.
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from issue112_pglogical_original_windows import (
    PINS, fetch_original, inspect_zip, require, validate_source_registry, verify_metadata,
)
from issue112_pglogical_pe_import_inventory import BINARIES, MODULE, pe_imports

MAX_MODULES = 160
MAX_LOCAL_SIZE = 32_000_000
MAX_DEPTH = 8
API_SET_PREFIXES = ("api-ms-win-", "ext-ms-win-")
ORIGINAL_PREFIX = {"lib/pglogical.dll", "lib/pglogical_output.dll",
                   "bin/pglogical_create_subscriber.exe"}


def classify(name: str, pgroot: Path, system32: Path,
             original_names: frozenset[str]):
    """A bounded *candidate* file location; never an assertion of loader order."""
    require(type(name) is str and MODULE.fullmatch(name) is not None,
            "untrusted DLL/EXE import module")
    low = name.lower()
    if low.startswith(API_SET_PREFIXES):
        return "API_SET_CONTRACT", None
    if low in original_names:
        return "PROVIDER_ORIGINAL", None
    for label, directory in (("EDB_BIN", pgroot / "bin"),
                             ("EDB_LIB", pgroot / "lib"),
                             ("WINDOWS_SYSTEM32", system32)):
        candidate = directory / name
        if candidate.is_file():
            return label, candidate
    return "UNRESOLVED", None


def inventory(payload: dict[str, bytes], pgroot: Path, system32: Path):
    original_names = frozenset(Path(k).name.lower() for k in ORIGINAL_PREFIX)
    require(set(ORIGINAL_PREFIX) <= set(payload), "incomplete original binary set")
    queue = deque((k, payload[k], 0) for k in sorted(ORIGINAL_PREFIX))
    visited = set()
    records = []
    unresolved = set()
    opaque = set()
    while queue:
        identity, data, depth = queue.popleft()
        require(len(visited) < MAX_MODULES, "PE dependency graph exceeds bound")
        if identity in visited:
            continue
        visited.add(identity)
        try:
            imports = pe_imports(data)
        except (ValueError, UnicodeError) as exc:
            opaque.add(identity)
            records.append({"identity": identity, "peParsed": False,
                            "reason": type(exc).__name__})
            continue
        discovered = []
        for dep in sorted(set(imports["static"] + imports["delay"])):
            label, path = classify(dep, pgroot, system32, original_names)
            discovered.append({"name": dep, "candidate": label})
            if label == "UNRESOLVED":
                unresolved.add((identity, dep))
            if label in ("EDB_BIN", "EDB_LIB") and path is not None:
                key = f"{label}/{path.name.lower()}"
                if key not in visited and depth < MAX_DEPTH:
                    size = path.stat().st_size
                    if 256 <= size <= MAX_LOCAL_SIZE:
                        queue.append((key, path.read_bytes(), depth + 1))
                    else:
                        opaque.add(key + ":SIZE_UNINSPECTED")
                elif key not in visited:
                    opaque.add(key + ":DEPTH_UNINSPECTED")
        records.append({"identity": identity, "peParsed": True,
                        "staticCount": len(imports["static"]),
                        "delayCount": len(imports["delay"]),
                        "imports": discovered})
    return {"inspectedPEs": len(visited), "entries": records,
            "unresolved": sorted([f"{src}:{dep}" for src, dep in unresolved]),
            "unparsedOrUninspected": sorted(opaque),
            "system32Transitive": "NOT_INSPECTED",
            "apiSetMapping": "NOT_PROVEN",
            "windowsLoaderClosure": False,
            "allRuntimeBranches": False,
            "componentRightsAndNotices": False,
            "downloadAuthorized": False, "mirrorAuthorized": False,
            "redistributionAuthorized": False, "publisherAuthorized": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pg", type=int, required=True, choices=sorted(PINS))
    args = parser.parse_args()
    require(os.getenv("GITHUB_ACTIONS") == "true" and
            os.getenv("GITHUB_REPOSITORY") == "pgextwin/catalog" and
            os.getenv("GITHUB_EVENT_NAME") == "pull_request" and
            os.getenv("RUNNER_OS") == "Windows" and
            bool(os.getenv("RUNNER_TEMP")) and bool(os.getenv("GH_TOKEN")),
            "authentic, ephemeral PR-only Windows audit required")
    pgroot_string = os.getenv("PGROOT")
    require(bool(pgroot_string), "pinned EDB PGROOT absent")
    pgroot = Path(pgroot_string).resolve()
    pgconfig = pgroot / "bin" / "pg_config.exe"
    require(pgconfig.is_file(), "EDB pg_config.exe absent")
    version = subprocess.run([str(pgconfig), "--version"], capture_output=True,
                             text=True, timeout=15, check=True).stdout.strip()
    require(version.startswith("PostgreSQL " + str(args.pg) + ".") or version == "PostgreSQL " + str(args.pg),
            "installed PostgreSQL major does not match original")
    system = os.getenv("SystemRoot") or os.getenv("WINDIR")
    require(bool(system), "Windows SystemRoot absent")
    system32 = Path(system).resolve() / "System32"
    require(system32.is_dir(), "Windows System32 absent")
    asset_id, length, sha = PINS[args.pg]
    validate_source_registry(args.pg, asset_id, length, sha)
    url = verify_metadata(args.pg, asset_id, length, sha)
    payload = inspect_zip(fetch_original(url, length, sha), args.pg)
    result = inventory(payload, pgroot, system32)
    result.update({"pgMajor": args.pg, "assetId": asset_id,
                   "originalSha256": sha, "originalBytes": length,
                   "trust": "CANDIDATE_ONLY_SOURCE_IMPORTED_PE_RESOLUTION"})
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    print("ORIGINAL_HASH=PASS PE_IMPORT_RESOLUTION_INVENTORY=COMPLETE "
          "SYSTEM32_TRANSITIVE=UNVERIFIED WINDOWS_LOADER_CLOSURE=UNVERIFIED")
    print("PATCH_RIGHTS=UNVERIFIED NOTICE_CLOSURE=UNVERIFIED "
          "GET=DENY MIRROR=DENY REDISTRIBUTION=DENY PUBLISH=DENY")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("PGLOGICAL_DEPENDENCY_INVENTORY_DENY:", exc, file=sys.stderr)
        raise SystemExit(1) from exc
