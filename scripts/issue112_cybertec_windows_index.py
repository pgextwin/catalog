#!/usr/bin/env python3
"""Metadata-only Cybertec PGEE Windows extension index observer (Issue #112).

Public directory listings are untrusted. This module never fetches ZIP bytes,
claims community PostgreSQL/EDB ABI compatibility, or authorizes distribution.
"""
import argparse
from html.parser import HTMLParser
import json
import re
import urllib.request

BASE = "https://repository.cybertec.at/windows/public/"
MAJORS = ("14", "15", "16", "17", "18")
MAX_INDEX_BYTES = 512 * 1024
MAX_LINKS = 500
# Cybertec also uses "pg_hint_plan-16-16-public-..." in addition to normal names.
ASSET = re.compile(
    r"(?P<extension>[a-z][a-z0-9_]{1,40})-(?P<major>1[4-8])"
    r"(?:-(?P<extra_major>1[4-8]))?-public-"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9_.-]{0,110})\.zip\Z"
)
PLAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,170}\Z")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("Cybertec index redirect not allowed")


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and isinstance(value, str):
                self.hrefs.append(value)
                if len(self.hrefs) > MAX_LINKS:
                    raise ValueError("Unbounded index link count")


def parse_index(content, major):
    if major not in MAJORS or type(content) is not bytes or not 0 < len(content) <= MAX_INDEX_BYTES:
        raise ValueError("Invalid PG major or bounded HTML input")
    parser = Links()
    parser.feed(content.decode("utf-8", errors="strict"))
    if not parser.hrefs:
        raise ValueError("Empty or unrecognized Cybertec index")
    found = {}
    for href in parser.hrefs:
        # Never normalize or follow untrusted HTML paths, URLs or query fragments.
        if href == "../":
            continue
        if not PLAIN.fullmatch(href):
            if ".zip" in href.lower():
                raise ValueError("Unsafe ZIP link in Cybertec listing")
            continue
        if not href.endswith(".zip"):
            continue
        match = ASSET.fullmatch(href)
        if match is None:
            continue
        if match.group("major") != major or match.group("extra_major") not in (None, major):
            raise ValueError("PG major mismatch in Cybertec package filename")
        if href in found:
            raise ValueError("Duplicate Cybertec ZIP filename")
        found[href] = {
            "extension": match.group("extension"), "pgMajor": major,
            "providerBuildLabelUntrusted": match.group("version"),
            "fileName": href,
            "originalUrlUntrusted": f"{BASE}{major}/extension/{href}",
            "originalBytesVerified": False, "originalSha256Verified": False,
            "upstreamVersionVerified": False,
            "communityPostgresqlAbiVerified": False,
            "producerProvenanceVerified": False,
            "licenseNoticeClosureVerified": False,
            "independentSignedAdmission": False,
            "publicGetAuthorized": False, "mirrorAuthorized": False,
            "publisherAuthorized": False, "releaseAuthorized": False,
        }
    if not found:
        raise ValueError("No recognizable Cybertec PG-major ZIP candidates")
    return [found[name] for name in sorted(found)]


def fetch_index(major, *, opener=None):
    if major not in MAJORS:
        raise ValueError("Unsupported PG major")
    url = f"{BASE}{major}/extension/"
    if opener is None:
        opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, headers={
        "Accept": "text/html", "User-Agent": "pgextwin-index-metadata-only/1"
    })
    with opener.open(request, timeout=20) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("Wrong canonical Cybertec index response")
        if not response.headers.get("Content-Type", "").lower().startswith("text/html"):
            raise ValueError("Unexpected Cybertec index media type")
        body = response.read(MAX_INDEX_BYTES + 1)
    return parse_index(body, major)


def collect(indexes):
    if type(indexes) is not dict or not indexes:
        raise ValueError("No PG index observations")
    rows = []
    denied_fields = ("originalBytesVerified", "originalSha256Verified",
                     "upstreamVersionVerified", "communityPostgresqlAbiVerified",
                     "producerProvenanceVerified", "licenseNoticeClosureVerified",
                     "independentSignedAdmission", "publicGetAuthorized",
                     "mirrorAuthorized", "publisherAuthorized",
                     "releaseAuthorized")
    for major in sorted(indexes, key=int):
        if major not in MAJORS:
            raise ValueError("Unsupported major in collected observations")
        entries = indexes[major]
        if not isinstance(entries, list) or not entries:
            raise ValueError("Missing major index")
        for entry in entries:
            if (type(entry) is not dict or entry.get("pgMajor") != major or
                    any(entry.get(field) is not False for field in denied_fields)):
                raise ValueError("Index candidate trust escalation")
        rows.extend(entries)
    coverage = {}
    for entry in rows:
        coverage.setdefault(entry["extension"], set()).add(entry["pgMajor"])
    return {
        "schemaVersion": "pgextwin-issue112-cybertec-windows-index/v1",
        "origin": BASE, "trust": "UNTRUSTED_DIRECTORY_METADATA_ONLY",
        "providerPackaging": "CYBERTEC_PGEE_COMMUNITY_PG_COMPATIBILITY_UNVERIFIED",
        "pgMajorsObserved": sorted(indexes, key=int),
        "zipCandidates": len(rows),
        "extensionNamesObserved": len(coverage),
        "completeObservedFiveMajorNames": sorted(
            name for name, majors in coverage.items() if set(MAJORS) <= majors),
        "latestVersionResolution": "NOT_VERIFIED",
        "sourceArchiveDownloaded": False,
        "binaryArchiveDownloaded": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "publisherAuthorized": False, "releaseAuthorized": False,
        "candidates": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg", choices=MAJORS,
                        help="One index; otherwise all PG14-18 indexes")
    args = parser.parse_args()
    indexes = {m: fetch_index(m) for m in ((args.pg,) if args.pg else MAJORS)}
    result = collect(indexes)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    print("CYBERTEC_METADATA_ONLY=YES PACKAGE_COMPATIBILITY=UNVERIFIED "
          "LATEST=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
