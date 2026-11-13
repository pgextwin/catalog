#!/usr/bin/env python3
"""Read-only PE import graph for an exact OSGeo original bundle; never grants GET.

Static PE import/delay-import coverage is not proof of dynamic LoadLibrary
resolution, completeness of third-party license notices or binary provenance.
"""
import json
from pathlib import Path
import re
import struct
import tempfile
import zipfile

from issue112_osgeo_rights_audit import (NAME, ORIGIN, SHA256, SIZE,
                                         audit_archive, read_original)

MAX_DLL_BYTES = 64 * 1024 * 1024
NAME_PATTERN = re.compile(r"[A-Za-z0-9_.+-]{1,255}\.(?:dll|exe)\Z", re.IGNORECASE)


# Exact OS DLL-name hints only. No binary path, signature, version, or runtime
# resolution is established by seeing one of these strings in a PE import table.
WINDOWS_SYSTEM_NAME_HINTS = frozenset({
    "advapi32.dll", "bcrypt.dll", "crypt32.dll", "dnsapi.dll",
    "dwrite.dll", "gdi32.dll", "gdiplus.dll", "imm32.dll",
    "iphlpapi.dll", "kernel32.dll", "msimg32.dll", "msvcrt.dll",
    "odbc32.dll", "odbccp32.dll", "ole32.dll", "rpcrt4.dll",
    "secur32.dll", "shell32.dll", "shlwapi.dll", "user32.dll",
    "usp10.dll", "wldap32.dll", "ws2_32.dll",
})


def triage_unbundled_imports(records, imports):
    """Attribute each unbundled import to exact consumers; do not grant closure.

    These are investigation hints, not verified DLL providers. Unknown names
    always stay unresolved. GUI path grouping never grants permission to omit
    a component from the original archive or silently accept its dependencies.
    """
    requesters = {name: [] for name in imports}
    for record in records:
        if record["analysis"] != "AMD64_PE32_PLUS":
            continue
        for name in record["notBundledImports"]:
            if name not in requesters:
                raise ValueError("Unaccounted external import in PE graph")
            requesters[name].append(record["path"])
    report = []
    for name in sorted(requesters):
        if name in WINDOWS_SYSTEM_NAME_HINTS:
            category = "WINDOWS_OS_DLL_NAME_ONLY_UNVERIFIED"
        elif name == "postgres.exe":
            category = "POSTGRES_SERVER_HOST_NAME_ONLY_UNVERIFIED"
        else:
            category = "UNRESOLVED_NONBUNDLED_COMPONENT"
        consumers = sorted(set(requesters[name]))
        if not consumers:
            raise ValueError("Unbundled import lacks referencing DLL")
        report.append({
            "name": name, "category": category, "referencedBy": consumers,
            "onlyReferencedFromGuiDirectory": all(
                "/bin/postgisgui/" in "/" + path.lower() for path in consumers),
            "resolvedOnTargetWindows": False,
        })
    return report


def core_server_import_paths(records):
    """Trace PostGIS/pgRouting server DLL imports without using GUI-only copies.

    Static name reachability is not Windows loader resolution. In particular,
    the EDB-installed libcurl may replace the original OSGeo libcurl at
    runtime; this graph deliberately does not infer such substitutions.
    """
    server = {}
    gui_names = set()
    for record in records:
        path = record["path"].lower()
        name = path.rsplit("/", 1)[-1]
        if "/bin/postgisgui/" in "/" + path:
            gui_names.add(name)
            continue
        if "/bin/" not in "/" + path and "/lib/" not in "/" + path:
            continue
        if name in server:
            raise ValueError("Ambiguous server DLL basename: " + name)
        server[name] = record

    # pgRouting's Windows DLL ABI name is versioned independently from the
    # PostGIS bundle and the PostgreSQL major. The former PG18-only 4.0
    # assumption silently omitted valid PG14-17 server roots from the graph.
    # Select exactly one versioned non-GUI server DLL, never infer its version
    # from a ZIP filename or promote a static name to runtime resolution.
    routing = sorted(name for name in server if re.fullmatch(
        r"libpgrouting-[0-9]+(?:[.][0-9]+)+[.]dll", name))
    if len(routing) > 1:
        raise ValueError("Ambiguous versioned pgRouting server DLL roots")
    routing_root = routing[0] if routing else "libpgrouting-<version>.dll"
    roots = ("postgis-3.dll", routing_root)
    missing_roots = sorted(root for root in roots if root not in server)
    pending = [(name, [name]) for name in roots if name in server]
    visited = set()
    external = {}
    unparsed = []
    while pending:
        name, chain = pending.pop(0)
        if name in visited:
            continue
        visited.add(name)
        entry = server.get(name)
        if entry is None:
            external[name] = {
                "name": name, "chain": chain,
                "presentOnlyInExcludedGuiTree": name in gui_names,
            }
            continue
        if entry["analysis"] != "AMD64_PE32_PLUS":
            unparsed.append(entry["path"])
            continue
        for imported in sorted(set(entry["staticImports"] + entry["delayImports"])):
            if imported not in visited:
                pending.append((imported, chain + [imported]))
    unresolved = sorted(
        (entry for name, entry in external.items()
         if name not in WINDOWS_SYSTEM_NAME_HINTS and name != "postgres.exe"),
        key=lambda entry: entry["name"])
    return {
        "roots": list(roots),
        "selectedVersionedPgRoutingServerDll": routing[0] if routing else None,
        "missingRoots": missing_roots,
        "reachableServerModuleCount": sum(x in server for x in visited),
        "unparsedReachableServerDlls": sorted(unparsed),
        "unresolvedThirdPartyImportPaths": unresolved,
        "guiTreeExcludedFromServerScope": True,
        "staticServerGraphTraversed": not missing_roots and not unparsed,
        "effectiveWindowsLoaderResolutionVerified": False,
        "independentSignedAdmission": False,
        "downloadAuthorized": False,
    }


def u16(data, at):
    if at < 0 or at + 2 > len(data):
        raise ValueError("PE u16 out of bounds")
    return struct.unpack_from("<H", data, at)[0]


def u32(data, at):
    if at < 0 or at + 4 > len(data):
        raise ValueError("PE u32 out of bounds")
    return struct.unpack_from("<I", data, at)[0]


def u64(data, at):
    if at < 0 or at + 8 > len(data):
        raise ValueError("PE u64 out of bounds")
    return struct.unpack_from("<Q", data, at)[0]


def static_imports(data):
    """Return (ordinary imports, delay imports) for one PE32+ AMD64 DLL."""
    if len(data) < 256 or data[:2] != b"MZ":
        raise ValueError("Not a PE DLL")
    pe = u32(data, 0x3c)
    if pe > 1024 * 1024 or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("Invalid PE signature")
    if u16(data, pe + 4) != 0x8664:
        raise ValueError("Not AMD64")
    section_count = u16(data, pe + 6)
    optional_size = u16(data, pe + 20)
    optional = pe + 24
    if not 1 <= section_count <= 96 or optional_size < 128 or \
            optional + optional_size + 40 * section_count > len(data) or \
            u16(data, optional) != 0x20b:
        raise ValueError("Invalid PE32+ headers")
    image_base = u64(data, optional + 24)
    directory_count = u32(data, optional + 108)
    sections = []
    for i in range(section_count):
        p = optional + optional_size + i * 40
        sections.append((u32(data, p + 12),
                         max(u32(data, p + 8), u32(data, p + 16)),
                         u32(data, p + 20), u32(data, p + 16)))

    def translate(rva, length=1):
        for va, virtual_length, raw, raw_length in sections:
            if va <= rva and rva - va + length <= virtual_length and \
                    rva - va + length <= raw_length:
                offset = raw + rva - va
                if offset + length <= len(data):
                    return offset
        raise ValueError("Unmapped or out-of-bounds import RVA")

    def dllname(rva):
        off = translate(rva)
        end = data.find(b"\0", off, min(len(data), off + 257))
        if end < 0:
            raise ValueError("Unterminated PE import name")
        try:
            name = data[off:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("Non-ASCII PE import name") from exc
        if not NAME_PATTERN.fullmatch(name):
            raise ValueError("Unsafe PE import DLL name")
        return name.lower()

    def directory(index, entry_size, name_offset, attrs_offset=None):
        if directory_count <= index:
            return []
        entry = optional + 112 + index * 8
        if entry + 8 > optional + optional_size:
            raise ValueError("Truncated PE directory table")
        rva, size = u32(data, entry), u32(data, entry + 4)
        if rva == 0 and size == 0:
            return []
        if rva == 0 or size < entry_size or size > 1024 * 1024:
            raise ValueError("Invalid PE import directory")
        result = []
        for offset in range(0, size - entry_size + 1, entry_size):
            desc = translate(rva + offset, entry_size)
            raw = data[desc:desc + entry_size]
            if raw == bytes(entry_size):
                return sorted(set(result))
            name_rva = u32(data, desc + name_offset)
            if attrs_offset is not None and not (u32(data, desc + attrs_offset) & 1):
                if name_rva < image_base:
                    raise ValueError("Invalid delay-load VA")
                name_rva -= image_base
            result.append(dllname(name_rva))
        raise ValueError("Missing import directory terminator")

    return directory(1, 20, 12), directory(13, 32, 4, 0)


def dependency_inventory(archive_path):
    with zipfile.ZipFile(archive_path) as archive:
        dlls = sorted((x for x in archive.infolist()
                       if not x.is_dir() and x.filename.lower().endswith(".dll")),
                      key=lambda x: x.filename)
        bundled = {}
        for x in dlls:
            bundled.setdefault(x.filename.rsplit("/", 1)[-1].lower(), []).append(x.filename)
        records = []
        all_external = set()
        for entry in dlls:
            if not 0 < entry.file_size <= MAX_DLL_BYTES:
                raise ValueError("DLL outside bounded import inspection")
            with archive.open(entry) as stream:
                data = stream.read(MAX_DLL_BYTES + 1)
            if len(data) != entry.file_size:
                raise ValueError("Truncated PE member")
            try:
                imports, delayed = static_imports(data)
            except ValueError as exc:
                records.append({"path": entry.filename,
                                "analysis": "NOT_PARSED", "reason": str(exc)})
                continue
            required = sorted(set(imports) | set(delayed))
            external = sorted(x for x in required if x not in bundled)
            all_external.update(external)
            records.append({"path": entry.filename, "analysis": "AMD64_PE32_PLUS",
                            "staticImports": imports, "delayImports": delayed,
                            "bundledImports": sorted(x for x in required if x in bundled),
                            "notBundledImports": external})
    return {
        "schemaVersion": "pgextwin-osgeo-pe-dependency-inventory-nonpublishing/v1",
        "source": ORIGIN, "expectedOriginalBytes": SIZE,
        "expectedOriginalSha256": SHA256,
        "dllCount": len(records),
        "parsedPeCount": sum(x["analysis"] == "AMD64_PE32_PLUS" for x in records),
        "nonParsed": [x for x in records if x["analysis"] == "NOT_PARSED"],
        "ambiguousBundledNames": {k: v for k, v in sorted(bundled.items()) if len(v) > 1},
        "importsNotInBundle": sorted(all_external),
        "unbundledImportTriage": triage_unbundled_imports(records, all_external),
        "unresolvedNonbundledImports": sorted(
            name for name in all_external
            if name not in WINDOWS_SYSTEM_NAME_HINTS and name != "postgres.exe"),
        "dllImports": records,
        "coreServerImportPaths": core_server_import_paths(records),
        "staticImportEnumerationCompleted": not any(x["analysis"] == "NOT_PARSED" for x in records),
        "dynamicDependenciesVerified": False,
        "targetWindowsImportResolutionVerified": False,
        "thirdPartyNoticesVerified": False,
        "sourceToBinaryProvenanceVerified": False,
        "independentSignedAdmission": False,
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
        "publisherAuthorized": False,
    }


def main():
    with tempfile.TemporaryDirectory(prefix="pgextwin-osgeo-deps-") as directory:
        path = Path(directory) / NAME
        size, sha = read_original(ORIGIN, path)
        if (size, sha) != (SIZE, SHA256):
            raise ValueError("OSGeo original bytes have changed; deny")
        rights = audit_archive(path)
        graph = dependency_inventory(path)
    print(json.dumps({"licenseFiles": rights["licenseFiles"], **graph},
                     sort_keys=True, separators=(",", ":")))
    print("OSGEO_IMPORT_GRAPH=OBSERVED DYNAMIC_DEPENDENCY_CLOSURE=DENY "
          "THIRD_PARTY_NOTICES=DENY BINARY_PROVENANCE=DENY PUBLIC_GET=DENY "
          "MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
