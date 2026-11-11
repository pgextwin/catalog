#!/usr/bin/env python3
"""Nonpublishing OSGeo bundle original-byte pilot; no extraction or admission.

The JSON input is explicitly untrusted metadata from the existing index scanner.
The resulting digest and archive observations are NOT a signature, ABI/runtime
proof, licensing clearance, or permission for users' CLI to download a bundle.
"""
import argparse
import hashlib
import json
import pathlib
import re
import stat
import struct
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ALLOWED_HOSTS = frozenset(("download-cache.osgeo.org", "ftp2.osuosl.org"))
SOURCE_PREFIX = "/postgis/windows/"
MAX_DOWNLOAD = 256 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 25000
NAME = re.compile(r"postgis-bundle-pg(1[4-8])-([0-9]+\.[0-9]+\.[0-9]+)x64\.zip\Z")


def require(test, why):
    if not test:
        raise ValueError("OSGeo original-byte pilot DENY: " + why)


def choose(snapshot):
    """Choose one current bundle candidate without adding authority."""
    require(type(snapshot) is dict and
            snapshot.get("schemaVersion") == "pgextwin-osgeo-postgis-windows-directory-snapshot/v1" and
            snapshot.get("sourceKind") == "UNTRUSTED_DIRECTORY_METADATA_ONLY" and
            snapshot.get("publicationAuthorized") is False and
            snapshot.get("redistributionAuthorized") is False,
            "invalid metadata-only snapshot")
    index = snapshot.get("sourceIndex")
    require(index in ("https://download-cache.osgeo.org/postgis/windows/",
                      "https://ftp2.osuosl.org/pub/osgeo/download/postgis/windows/"),
            "unknown source index")
    selection = snapshot.get("latestBundleSelection")
    require(type(selection) is dict and
            selection.get("scope") == "UNVERIFIED_METADATA_SELECTION_ONLY" and
            selection.get("mode") == "single-newest-bundle" and
            selection.get("downloadAuthorized") is False and
            selection.get("mirrorAuthorized") is False and
            type(selection.get("selected")) is list and
            len(selection["selected"]) == 1,
            "requires one denied latest bundle")
    row = selection["selected"][0]
    require(type(row) is dict and
            row.get("downloadAuthorized") is False and
            row.get("mirrorAuthorized") is False and
            type(row.get("fileName")) is str and
            type(row.get("pgMajor")) is str and
            type(row.get("version")) is str and
            type(row.get("sourceRelativePath")) is str,
            "source selection escalated or invalid")
    match = NAME.fullmatch(row["fileName"])
    require(match is not None and match.group(1) == row["pgMajor"] and
            match.group(2) == row["version"] and
            row["sourceRelativePath"] == "pg" + row["pgMajor"] + "/" + row["fileName"],
            "unsupported PG/ZIP identity or unsafe path")
    return index + row["sourceRelativePath"], row



def choose_major(snapshot, pg_major):
    """Select exactly one PG14-17 original from complete denied per-PG metadata.

    This is only an inspection selector. A directory listing is not provenance
    or a trusted digest, and no candidate may enter a public GET path.
    """
    require(pg_major in ("14", "15", "16", "17"), "unsupported per-PG pilot")
    require(type(snapshot) is dict and
            type(snapshot.get("latestBundleSelection")) is dict,
            "missing denied per-PG selection")
    selection = snapshot["latestBundleSelection"]
    require(selection.get("scope") == "UNVERIFIED_METADATA_SELECTION_ONLY" and
            selection.get("mode") == "latest-per-supported-pg" and
            selection.get("downloadAuthorized") is False and
            selection.get("mirrorAuthorized") is False and
            type(selection.get("selected")) is list and
            len(selection["selected"]) == 5,
            "incomplete or untrusted latest-per-PG selection")
    found = {}
    for row in selection["selected"]:
        # Reuse the single-original path/major/version and DENY contract for
        # every row, not merely for the selected major.
        single = {**snapshot, "latestBundleSelection": {
            **selection, "mode": "single-newest-bundle", "selected": [row]}}
        url, checked = choose(single)
        major = checked["pgMajor"]
        require(major not in found, "duplicate PostgreSQL major")
        found[major] = (url, checked)
    require(set(found) == {"14", "15", "16", "17", "18"},
            "missing or unexpected supported PostgreSQL major")
    return found[pg_major]


def safe_endpoint(url):
    p = urllib.parse.urlsplit(url)
    require(p.scheme == "https" and p.hostname in ALLOWED_HOSTS and
            p.username is None and p.password is None and p.port in (None, 443) and
            p.path.startswith((SOURCE_PREFIX, "/pub/osgeo/download/postgis/windows/")) and
            not p.query and not p.fragment, "untrusted redirect/transport")
    return url


class OriginRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        safe_endpoint(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_original(url, dest, opener=None):
    """Bounded source GET with finite retry of transient origin HTTP failures.

    Never retry a digest/size mismatch, unsafe redirect, unexpected 2xx/4xx,
    or a local archive validation failure; never fall back to another origin.
    """
    safe_endpoint(url)
    opener = opener or urllib.request.build_opener(OriginRedirects())
    request = urllib.request.Request(
        url, headers={"User-Agent": "pgextwin-issue112-osgeo-nonpublishing/1"})
    transient = frozenset((502, 503, 504, 525))
    for attempt in range(3):
        digest = hashlib.sha256()
        size = 0
        try:
            with opener.open(request, timeout=90) as response, open(dest, "wb") as out:
                safe_endpoint(response.geturl())
                require(response.status == 200, "origin did not return HTTP 200")
                length = response.headers.get("Content-Length")
                require(length is None or
                        (length.isdecimal() and int(length) <= MAX_DOWNLOAD),
                        "oversized/invalid Content-Length")
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    require(size <= MAX_DOWNLOAD, "bounded download exceeded")
                    digest.update(block)
                    out.write(block)
            require(0 < size <= MAX_DOWNLOAD and
                    (length is None or size == int(length)),
                    "incomplete original ZIP")
            return size, digest.hexdigest()
        except urllib.error.HTTPError as error:
            if error.code not in transient or attempt == 2:
                raise
            # Retry strictly the same approved URL; no redirected retry target,
            # no partial-file reuse and no content-integrity exception.
            dest.unlink(missing_ok=True)
            time.sleep(2 * (attempt + 1))
    raise AssertionError("unreachable finite GET retry state")


def pe_amd64(stream):
    head = stream.read(64)
    if len(head) < 64 or head[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", head, 0x3c)[0]
    if offset > 2_000_000:
        return False
    stream.seek(offset)
    signature = stream.read(6)
    return signature[:4] == b"PE\0\0" and signature[4:] == b"\x64\x86"


def inspect(path):
    with zipfile.ZipFile(path) as z:
        entries = z.infolist()
        require(0 < len(entries) <= MAX_MEMBERS, "invalid archive member count")
        seen, expanded = set(), 0
        controls, dlls = set(), []
        for entry in entries:
            name = entry.filename
            parts = name.rstrip("/").split("/")
            require(bool(name) and not name.startswith(("/", "\\")) and
                    "\\" not in name and ":" not in name and
                    all(p not in ("", ".", "..") for p in parts) and
                    name.casefold() not in seen, "unsafe path or case-fold collision")
            seen.add(name.casefold())
            require(not stat.S_ISLNK(entry.external_attr >> 16), "symlink prohibited")
            expanded += entry.file_size
            require(expanded <= MAX_EXPANDED and
                    entry.file_size <= max(entry.compress_size, 1) * 500,
                    "expanded size or ratio cap exceeded")
            if not entry.is_dir():
                if parts[-1] in ("postgis.control", "pgrouting.control"):
                    controls.add(parts[-1])
                if parts[-1].lower().endswith(".dll"):
                    dlls.append(entry)
        require(controls == {"postgis.control", "pgrouting.control"},
                "PostGIS and pgRouting control files both required")
        require(len(dlls) > 0, "Windows DLL absent")
        amd64 = 0
        for entry in dlls:
            with z.open(entry) as stream:
                if pe_amd64(stream):
                    amd64 += 1
        require(amd64 > 0, "no PE AMD64 DLL found")
        require(z.testzip() is None, "CRC mismatch")
        return {"zipMembers": len(entries), "uncompressedBytes": expanded,
                "postgisControl": True, "pgroutingControl": True,
                "peAmd64Dlls": amd64}


def run(snapshot, pg_major=None):
    url, row = (choose_major(snapshot, pg_major) if pg_major is not None
                else choose(snapshot))
    safe_endpoint(url)
    with tempfile.TemporaryDirectory(prefix="pgextwin-osgeo-original-") as folder:
        path = pathlib.Path(folder) / row["fileName"]
        size, sha256 = read_original(url, path)
        payload = inspect(path)
    result = {"status": "CANDIDATE_ONLY", "originalGetAndZipInspection": "PASS",
              "sourceUrl": url, "pgMajor": row["pgMajor"], "version": row["version"],
              "bytes": size, "sha256Observed": sha256, **payload,
              "independentSignatureVerified": False, "pgRuntimeVerified": False,
              "rightsReviewed": False, "dependenciesVerified": False,
              "downloadAuthorized": False, "mirrorAuthorized": False,
              "publisherAuthorized": False}
    print(json.dumps(result, sort_keys=True))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection-file", type=pathlib.Path, required=True)
    parser.add_argument("--pg-major", choices=("14", "15", "16", "17"),
                        help="Inspect exactly one unverified PG14-17 original")
    args = parser.parse_args()
    run(json.loads(args.selection_file.read_text("utf-8")), pg_major=args.pg_major)
