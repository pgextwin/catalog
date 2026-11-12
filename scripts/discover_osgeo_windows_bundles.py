#!/usr/bin/env python3
"""Bounded read-only OSGeo PostGIS Windows directory history discovery.

Directory HTML is UNTRUSTED and exposes no ZIP, installer, license, SHA256,
signature, dependency, ABI or publication authorization. No ZIP/EXE/MD5 GET.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import urllib.request

BASES = {
    "osgeo-cache": "https://download-cache.osgeo.org/postgis/windows/",
    "osu-mirror": "https://ftp2.osuosl.org/pub/osgeo/download/postgis/windows/",
}
PG_DIRECTORY = re.compile(r"pg[0-9]{2}/\Z")
FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,200}\Z")
BINARY_NAME = re.compile(r"postgis[^/]*\.(?:zip|exe)\Z", re.I)
BUNDLE_ZIP = re.compile(
    r"postgis-bundle-pg([0-9]{2})-([0-9]+\.[0-9]+\.[0-9]+)x64\.zip\Z")
BUNDLE_EXE = re.compile(
    r"postgis-bundle-pg([0-9]{2})x64-setup-([0-9]+\.[0-9]+\.[0-9]+)-[0-9]+\.exe\Z")
MAX_DIRECTORY_ENTRIES = 4000
MAX_LISTING_BYTES = 3_000_000
MAX_PG_DIRECTORIES = 40


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and isinstance(value, str):
                self.links.append(value)


def parse_listing(html):
    if not isinstance(html, (bytes, str)) or len(html) > MAX_LISTING_BYTES:
        raise ValueError("Directory listing is missing/oversized")
    parser = Links()
    parser.feed(html.decode("utf-8") if isinstance(html, bytes) else html)
    if len(parser.links) > MAX_DIRECTORY_ENTRIES:
        raise ValueError("Directory listing contains too many links")
    found = set()
    for href in parser.links:
        if href in ("../", "./", "/", "?C=N;O=D"):
            continue
        # Reject paths, URL encodings, credentials, query strings and delimiters;
        # no relative directory walking or non-OSGeo origin may be followed.
        if not (href.endswith("/") and PG_DIRECTORY.fullmatch(href)
                or href == "archive/"
                or FILE_NAME.fullmatch(href)):
            continue
        if href in found:
            raise ValueError("Duplicate directory entry")
        found.add(href)
    if not found:
        raise ValueError("Directory listing has no eligible entries")
    return sorted(found)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("Untrusted directory redirect")


def fetch_index(root, directory):
    if root not in BASES:
        raise ValueError("Unknown pinned index mirror")
    if directory not in ("",) and not (
            PG_DIRECTORY.fullmatch(directory) or
            re.fullmatch(r"pg[0-9]{2}/archive/", directory)):
        raise ValueError("Untrusted index path")
    url = BASES[root] + directory
    opener = urllib.request.build_opener(NoRedirect())
    req = urllib.request.Request(
        url, headers={"User-Agent": "pgextwin-osgeo-metadata-only/1",
                      "Accept": "text/html"})
    with opener.open(req, timeout=25) as response:
        if response.status != 200 or response.url != url:
            raise ValueError("Wrong directory response")
        if not response.headers.get("Content-Type", "").lower().startswith("text/html"):
            raise ValueError("Unexpected index MIME type")
        body = response.read(MAX_LISTING_BYTES + 1)
    return parse_listing(body)


def normalize_major(pgdir):
    n = int(pgdir[2:-1])
    if n < 100 and n >= 80:
        return str(n // 10) + "." + str(n % 10)
    return str(n)


def scan(root, fetch):
    if root not in BASES:
        raise ValueError("Untrusted mirror")
    names = fetch("")
    pgdirs = [name for name in names if PG_DIRECTORY.fullmatch(name)]
    if not pgdirs or len(pgdirs) > MAX_PG_DIRECTORIES:
        raise ValueError("Unexpected PG directory coverage")
    dirs = {}
    # Concurrent bounded discovery; each GET is a directory *index*, never a ZIP/EXE.
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(fetch, pgdirs))
    for directory, links in zip(pgdirs, results):
        if not links:
            raise ValueError("Empty PostgreSQL directory index")
        dirs[directory] = links
    archive_dirs = [directory + "archive/" for directory in pgdirs
                    if "archive/" in dirs[directory]]
    with ThreadPoolExecutor(max_workers=6) as pool:
        archives = list(pool.map(fetch, archive_dirs))
    for directory, links in zip(archive_dirs, archives):
        if not links:
            raise ValueError("Empty historical archive index")
        dirs[directory] = links
    candidates = []
    all_filenames = set()
    for directory in sorted(dirs):
        major = normalize_major(directory.split("/")[0] + "/")
        for filename in dirs[directory]:
            if not BINARY_NAME.fullmatch(filename):
                continue
            source_key = directory + filename
            if source_key in all_filenames:
                raise ValueError("Duplicate directory ZIP identity")
            all_filenames.add(source_key)
            parsed = BUNDLE_ZIP.fullmatch(filename) or BUNDLE_EXE.fullmatch(filename)
            parsed_major = normalize_major("pg" + parsed.group(1) + "/") if parsed else None
            if parsed_major is not None and parsed_major != major:
                raise ValueError("Bundle filename/PG directory mismatch")
            entry = {
                "sourceRelativePath": source_key,
                "pgMajor": major,
                "packagedPostgisVersion": parsed.group(2) if parsed else None,
                "fileName": filename,
                "artifactKind": "bundle-zip" if filename.lower().endswith(".zip")
                                else "bundle-installer-exe",
                "historicalDirectory": directory.endswith("archive/"),
                "md5SidecarPresent": filename + ".md5" in dirs[directory],
                "bundleContentsVerified": False,
                "originalSha256Verified": False,
                "licensesAndNoticesVerified": False,
                "dependenciesAndAbiVerified": False,
                "provenanceVerified": False,
                "downloadAuthorized": False,
                "mirrorAuthorized": False,
            }
            candidates.append(entry)
    if not candidates:
        raise ValueError("No OSGeo Windows bundle candidates")
    return {
        "schemaVersion": "pgextwin-osgeo-postgis-windows-directory-snapshot/v1",
        "sourceIndex": BASES[root],
        "sourceKind": "UNTRUSTED_DIRECTORY_METADATA_ONLY",
        "publicationAuthorized": False,
        "redistributionAuthorized": False,
        "majorDirectories": len(pgdirs),
        "archiveDirectories": len(archive_dirs),
        "scannedIndexDirectories": 1 + len(dirs),
        "bundleFiles": len(candidates),
        "pgMajors": sorted({e["pgMajor"] for e in candidates}),
        "candidates": sorted(candidates, key=lambda e: e["sourceRelativePath"]),
    }



# Only non-EOL PG15-18 majors may be selected for NEW latest candidates.
# PG14/earlier directory history remains discoverable but never auto-selected.
# This metadata selector grants no GET, mirror, release or publish permission.
LATEST_SUPPORTED_MAJORS = frozenset({"15", "16", "17", "18"})


def select_latest_bundles(report, *, single_bundle=False):
    """Pick current ZIP names only; this is NOT a download or trust decision.

    Each selected ZIP remains explicitly unsigned, unverified and GET_DENY.
    In single-bundle mode one newest version is selected for a future
    PostGIS/pgRouting bundle pilot, with NO cross-PG compatibility claim.
    """
    if (type(report) is not dict or
            report.get("schemaVersion") !=
                "pgextwin-osgeo-postgis-windows-directory-snapshot/v1" or
            report.get("publicationAuthorized") is not False or
            report.get("redistributionAuthorized") is not False or
            type(report.get("candidates")) is not list):
        raise ValueError("Untrusted OSGeo source snapshot")
    by_pg = {}
    for entry in report["candidates"]:
        if type(entry) is not dict:
            raise ValueError("Malformed OSGeo candidate row")
        # Validate DENY on EVERY discovered row before skipping EOL/history.
        # Otherwise an excluded PG14/archived row could hide an attempted
        # authority escalation from the fail-closed audit.
        if any(entry.get(field) is not False for field in (
                "downloadAuthorized", "mirrorAuthorized",
                "bundleContentsVerified", "originalSha256Verified",
                "licensesAndNoticesVerified", "dependenciesAndAbiVerified",
                "provenanceVerified")):
            raise ValueError("OSGeo metadata attempted to escalate trust")
        if (entry.get("pgMajor") not in LATEST_SUPPORTED_MAJORS or
                entry.get("historicalDirectory") is not False or
                entry.get("artifactKind") != "bundle-zip"):
            continue
        filename = entry.get("fileName")
        parsed = BUNDLE_ZIP.fullmatch(filename) if type(filename) is str else None
        if parsed is None or normalize_major("pg" + parsed.group(1) + "/") != entry["pgMajor"]:
            continue
        if (entry.get("packagedPostgisVersion") != parsed.group(2) or
                entry.get("downloadAuthorized") is not False or
                entry.get("mirrorAuthorized") is not False or
                entry.get("bundleContentsVerified") is not False or
                entry.get("originalSha256Verified") is not False or
                entry.get("licensesAndNoticesVerified") is not False or
                entry.get("dependenciesAndAbiVerified") is not False or
                entry.get("provenanceVerified") is not False):
            raise ValueError("OSGeo metadata attempted to escalate trust")
        parts = tuple(map(int, parsed.group(2).split(".")))
        candidate = (parts, int(entry["pgMajor"]), entry["sourceRelativePath"])
        pg = entry["pgMajor"]
        if pg not in by_pg or candidate > by_pg[pg][0]:
            by_pg[pg] = (candidate, entry)
    if not by_pg:
        raise ValueError("No current supported-major OSGeo ZIP candidates")
    picks = [x[1] for _, x in sorted(by_pg.items(), key=lambda x: int(x[0]))]
    if single_bundle:
        picks = [max(picks, key=lambda x: (
            tuple(map(int, x["packagedPostgisVersion"].split("."))),
            int(x["pgMajor"]), x["sourceRelativePath"]))]
    return {
        "scope": "UNVERIFIED_METADATA_SELECTION_ONLY",
        "mode": "single-newest-bundle" if single_bundle else "latest-per-supported-pg",
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
        "selected": [
            {"pgMajor": e["pgMajor"], "version": e["packagedPostgisVersion"],
             "fileName": e["fileName"],
             "sourceRelativePath": e["sourceRelativePath"],
             "downloadAuthorized": False, "mirrorAuthorized": False}
            for e in picks
        ],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--index", choices=sorted(BASES), default="osu-mirror")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--latest-only", action="store_true",
                   help="Include newest ZIP metadata for each supported PostgreSQL major")
    p.add_argument("--single-bundle", action="store_true",
                   help="Include one newest PostGIS/pgRouting bundle candidate (no PG ABI claim)")
    args = p.parse_args()
    report = scan(args.index, lambda directory: fetch_index(args.index, directory))
    if args.latest_only or args.single_bundle:
        if args.latest_only and args.single_bundle:
            p.error("Choose only one metadata-only selection mode")
        report["latestBundleSelection"] = select_latest_bundles(
            report, single_bundle=args.single_bundle)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    summary = {k: v for k, v in report.items()
               if k not in ("candidates", "pgMajors")}
    summary["downloadAuthorized"] = False
    summary["mirrorAuthorized"] = False
    print(json.dumps(summary, sort_keys=True))
    with open(os.environ.get("GITHUB_STEP_SUMMARY", os.devnull), "a",
              encoding="utf-8") as out:
        out.write("## OSGeo PostGIS bundle index (metadata-only)\n\n")
        out.write("Directories: " + str(report["scannedIndexDirectories"]) +
                  "; bundle files: " + str(report["bundleFiles"]) + "\n\n")
        out.write("No downloaded binary, source-payload inspection, SHA256, signature, "
                  "license, ABI or external distribution authority is claimed.\n")


if __name__ == "__main__":
    main()
