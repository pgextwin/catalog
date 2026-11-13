#!/usr/bin/env python3
"""Issue #112: nonpublishing PE import inventory of five original pglogical ZIPs.

Exact original bytes must pass the independent SHA256, ZIP safety, and
identity gates first. PE import names are inventory, NOT loader resolution,
transitive dependency closure, license clearance, or download authorization.
"""
from __future__ import annotations

import os
import re
import struct
import sys

from issue112_pglogical_original_windows import (
    PINS, fetch_original, inspect_zip, require, validate_source_registry,
    verify_metadata,
)

BINARIES = (
    "lib/pglogical.dll",
    "lib/pglogical_output.dll",
    "bin/pglogical_create_subscriber.exe",
)
MODULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,126}\.(?:dll|exe)", re.I)
MAX_PE = 3_000_000


def _u16(data, pos):
    require(0 <= pos <= len(data) - 2, "truncated PE u16")
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data, pos):
    require(0 <= pos <= len(data) - 4, "truncated PE u32")
    return struct.unpack_from("<I", data, pos)[0]


def pe_imports(data):
    """Return static and delay-loaded import names without claiming resolution."""
    require(isinstance(data, bytes) and 256 <= len(data) <= MAX_PE
            and data[:2] == b"MZ", "invalid PE DOS header")
    pe = _u32(data, 0x3c)
    require(pe + 24 <= len(data) and data[pe:pe + 4] == b"PE\x00\x00",
            "invalid PE signature")
    require(_u16(data, pe + 4) == 0x8664, "not AMD64 PE")
    section_count = _u16(data, pe + 6)
    opt_size = _u16(data, pe + 20)
    opt = pe + 24
    require(1 <= section_count <= 96 and 0xf0 <= opt_size <= 4096
            and opt + opt_size + section_count * 40 <= len(data),
            "invalid PE section/optional header bounds")
    require(_u16(data, opt) == 0x20b, "not PE32+")
    directories = _u32(data, opt + 108)
    require(2 <= directories <= 32 and opt + 112 + directories * 8 <= opt + opt_size,
            "invalid PE data directories")

    sections = []
    for index in range(section_count):
        sec = opt + opt_size + index * 40
        virtual_address = _u32(data, sec + 12)
        raw_size = _u32(data, sec + 16)
        raw_pointer = _u32(data, sec + 20)
        require(raw_pointer <= len(data) and raw_size <= len(data) - raw_pointer,
                "invalid PE section raw range")
        sections.append((virtual_address, raw_size, raw_pointer))

    def locate(rva, size):
        require(0 < rva <= 0xffffffff and 1 <= size <= MAX_PE,
                "invalid PE import RVA")
        for start, length, file_start in sections:
            if start <= rva and size <= length and rva - start <= length - size:
                pos = file_start + rva - start
                require(pos + size <= len(data), "PE import outside file")
                return pos
        raise ValueError("PGLOGICAL_INDEPENDENT_PILOT_DENY: unmapped PE import RVA")

    def name_at(rva):
        start = locate(rva, 1)
        end = data.find(b"\x00", start, min(len(data), start + 129))
        require(end > start, "missing/empty PE import module name")
        try:
            name = data[start:end].decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Invalid PE import module encoding") from exc
        require(MODULE.fullmatch(name) is not None, "unsafe PE import module name")
        return name.lower()

    def directory(index, width, name_field):
        if index >= directories:
            return []
        rva, length = _u32(data, opt + 112 + index * 8), _u32(
            data, opt + 116 + index * 8)
        require((rva == 0) == (length == 0), "inconsistent PE import directory")
        if not rva:
            return []
        require(width <= length <= 64_000, "invalid PE import directory size")
        results = []
        seen = set()
        for entry in range(128):
            pos = locate(rva + width * entry, width)
            record = data[pos:pos + width]
            if record == b"\x00" * width:
                return results
            if index == 13:
                require((_u32(data, pos) & 1) == 1,
                        "unsupported VA-mode delay import descriptor")
            module = name_at(_u32(data, pos + name_field))
            require(module not in seen, "duplicate PE import module descriptor")
            seen.add(module)
            results.append(module)
        raise ValueError("PGLOGICAL_INDEPENDENT_PILOT_DENY: unterminated import table")

    standard = directory(1, 20, 12)
    require(standard, "empty PE static import table")
    delayed = directory(13, 32, 4)
    return {"static": sorted(standard), "delay": sorted(delayed)}


def audit_all():
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_REPOSITORY") == "pgextwin/catalog"
            and os.environ.get("GITHUB_EVENT_NAME") == "pull_request"
            and os.environ.get("RUNNER_OS") == "Linux"
            and os.environ.get("GH_TOKEN"),
            "real read-only pull_request CI only")
    for major in sorted(PINS):
        asset_id, length, digest = PINS[major]
        validate_source_registry(major, asset_id, length, digest)
        url = verify_metadata(major, asset_id, length, digest)
        originals = inspect_zip(fetch_original(url, length, digest), major)
        for name in BINARIES:
            imports = pe_imports(originals[name])
            modules = sorted(set(imports["static"] + imports["delay"]))
            require(modules, "PE module has no inspectable dependencies")
            print(f"PG={major} FILE={name} STATIC={','.join(imports['static'])} "
                  f"DELAY={','.join(imports['delay']) or '-'}")
        print(f"PG={major} ORIGINAL_SHA256=PASS ZIP_SAFE=PASS PE_IMPORT_INVENTORY=PASS")
    print("TRANSITIVE_PE_CLOSURE=UNVERIFIED WINDOWS_LOADER_CLOSURE=UNVERIFIED")
    print("WINDOWS_PATCH_RIGHTS=UNVERIFIED NOTICE_CLOSURE=UNVERIFIED")
    print("CANDIDATE_ONLY=YES GET=DENY MIRROR=DENY REDISTRIBUTION=DENY PUBLISH=DENY")


if __name__ == "__main__":
    try:
        audit_all()
    except (OSError, ValueError, KeyError, struct.error) as exc:
        print("PGLOGICAL_PE_IMPORT_DENY:", str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
