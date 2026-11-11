#!/usr/bin/env python3
"""Read-only OSGeo source-index coverage for previously verified Windows bundles.

A directory filename, even if its version matches, is not an attestation of
source inputs, component rights, producer identity, or ZIP byte provenance.
No original ZIP/installer/source archive is downloaded by this script.
"""
import json
import re
import urllib.request

from discover_osgeo_windows_bundles import NoRedirect, parse_listing, MAX_LISTING_BYTES

ROOT = "https://download-cache.osgeo.org/postgis/windows/source/"
# Exact observed original binaries, NOT newly admitted distribution pins.
OBSERVED_BINARIES = {
    "14": "3.6.1", "15": "3.6.2", "16": "3.6.2",
    "17": "3.6.2", "18": "3.7.0",
}
SOURCE_FILE = re.compile(
    r"postgis-bundle-pg(1[4-8])x64-([0-9]+\.[0-9]+\.[0-9]+)-installer-src\.zip\Z"
)


def read_index(pg):
    if pg not in OBSERVED_BINARIES:
        raise ValueError("PG major outside audited original binary set")
    url = f"{ROOT}pg{pg}/"
    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(url, headers={
        "User-Agent": "pgextwin-issue112-source-index-metadata-only/1",
        "Accept": "text/html",
    })
    with opener.open(request, timeout=25) as response:
        if (response.status != 200 or response.url != url or
                not response.headers.get("Content-Type", "").lower().startswith("text/html")):
            raise ValueError("Untrusted OSGeo source listing response")
        content = response.read(MAX_LISTING_BYTES + 1)
    return parse_listing(content)


def audit(listings):
    """Compare exact filenames only; refuse caller-supplied trust assertions."""
    if type(listings) is not dict or set(listings) != set(OBSERVED_BINARIES):
        raise ValueError("Incomplete OSGeo source-major listing set")
    results = []
    for pg, binary_version in OBSERVED_BINARIES.items():
        names = listings[pg]
        if type(names) is not list or not names or len(names) != len(set(names)):
            raise ValueError("Empty/duplicate source directory listing")
        versions = []
        for name in names:
            if type(name) is not str:
                raise ValueError("Invalid source index member")
            match = SOURCE_FILE.fullmatch(name)
            if not match:
                # Only the exact installer source name pattern can support a name match.
                continue
            if match.group(1) != pg:
                raise ValueError("Cross-major OSGeo source filename")
            versions.append(match.group(2))
        versions = sorted(set(versions), key=lambda v: tuple(map(int, v.split("."))))
        matching = binary_version in versions
        results.append({
            "pgMajor": pg,
            "observedOriginalBundleVersion": binary_version,
            "sourceListingUrl": f"{ROOT}pg{pg}/",
            "listedInstallerSourceVersions": versions,
            "matchingInstallerSourceFilenameListed": matching,
            "installerSourceIsCompleteBinaryBuildInput": False,
            "producerToOriginalZipAttestationVerified": False,
            "componentLicenseNoticeClosureVerified": False,
            "publicGetAuthorized": False,
            "mirrorAuthorized": False,
            "publisherAuthorized": False,
            "releaseAuthorized": False,
            "status": "NAME_MATCH_ONLY_NOT_PROVENANCE" if matching
                      else "NO_MATCHING_INSTALLER_SOURCE_FILENAME_LISTED",
        })
    return {
        "schemaVersion": "pgextwin-issue112-osgeo-installer-source-gap/v1",
        "evidenceType": "UNTRUSTED_DIRECTORY_FILENAMES_ONLY",
        "originalZipDownloaded": False,
        "sourceArchiveDownloaded": False,
        "sourceToBinaryProvenanceVerified": False,
        "publicGetAuthorized": False,
        "mirrorAuthorized": False,
        "publisherAuthorized": False,
        "releaseAuthorized": False,
        "rows": results,
    }


def main():
    # Only five public directory-index GET requests, never any binary/archive.
    result = audit({pg: read_index(pg) for pg in OBSERVED_BINARIES})
    print(json.dumps(result, sort_keys=True))
    print("OSGEO_SOURCE_INDEX=OBSERVED PRODUCER_PROVENANCE=UNVERIFIED "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
