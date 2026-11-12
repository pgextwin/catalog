#!/usr/bin/env python3
"""Pin PostGIS tagged source-side rights references, not OSGeo binary provenance.

All reads are bounded HTTPS GitHub API GETs. No original ZIP, publication, signing,
authorization, artifact upload, or mirror is performed.
"""
import base64
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request

TAG = "3.7.0"
TAG_OBJECT = "37eb1427a9fa90834c5c4fea1347d096c81549d3"
COMMIT = "1fdbb1cbb0e076816be06c401c5a5a2cf2c487f9"
API = "https://api.github.com/repos/postgis/postgis"
BLOBS = {
    "LICENSE.TXT": "403c98bb6d2c550f629a639faa63cebe14ee3111",
    "COPYING": "d159169d1050894d3ea3b98e1c965c4058208fe1",
    "ci/winnie/package_postgis.sh": "54ec34672841ee282dadfe500e79c0063cf57349",
    "ci/winnie/winnie_common.sh": "19795c7413cd1114afa7b0864eef3cf7034dd900",
}
LICENSE_MARKERS = {
    "PostGIS": "GNU General Public License, either version 2 or (at your option) any",
    "PROJ": "Proj4 - https://proj.org -- X/MIT License",
    "GEOS": "GEOS - https://libgeos.org -- LGPL License",
    "LibXML": "LibXML - https://xmlsoft.org/ -- X/MIT License",
    "GDAL": "GDAL - https://gdal.org/ -- X/MIT Style License",
    "SFCGAL": "SFCGAL -- https://oslandia.gitlab.io/SFCGAL/ -- GPL/V2+",
    "CGAL": "SFCGAL relies on CGAL https://www.cgal.org/ -- GPL and LGPLV3",
}
PACKAGE_MARKERS = (
    "libcrypto-3-x64.dll", "libssl-3-x64.dll",
    "cp postgis/*.dll", "cp sfcgal/*.dll", "cp topology/*.dll",
    "cp raster/rt_pg/*.dll", "geos/rel-", "gdal/rel-",
    "PROJ_PATH", "CURL VERSION", "zip -r $package",
)
COMMON_MARKERS = (
    "GEOS_VER=3.15.0", "GDAL_VER=3.13.1", "PROJ_VER=9.8.1",
    "OVERRIDE", "OS_BUILD",
)

class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("Redirect rejected for immutable source evidence")

def public_get_json(url):
    if not url.startswith(API + "/") or len(url) > 300:
        raise ValueError("Unexpected original-source API URL")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "pgextwin-issue112-source-rights-deny-only",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    opener = urllib.request.build_opener(RejectRedirect())
    with opener.open(urllib.request.Request(url, headers=headers), timeout=15) as response:
        if response.status != 200:
            raise ValueError("Unexpected GitHub API response")
        data = response.read(256_001)
    if len(data) > 256_000:
        raise ValueError("Oversize upstream source evidence")
    return json.loads(data.decode("utf-8"))

def git_blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\\x00" + data).hexdigest()

def require_markers(text, markers, path):
    for marker in markers:
        if marker not in text:
            raise ValueError("Expected source-level statement missing: " + path + " / " + marker)

def audit(get_json=public_get_json, expected_blobs=None):
    # The replacement map is only for offline unit tests; production always pins BLOBS.
    expected = BLOBS if expected_blobs is None else expected_blobs
    if set(expected) != set(BLOBS) or any(not re.fullmatch(r"[0-9a-f]{40}", v) for v in expected.values()):
        raise ValueError("Invalid source evidence pin inventory")
    ref = get_json(API + "/git/ref/tags/" + TAG)
    if (ref.get("ref") != "refs/tags/" + TAG or
        ref.get("object") != {"sha": TAG_OBJECT, "type": "tag",
                              "url": API + "/git/tags/" + TAG_OBJECT}):
        raise ValueError("Unexpected annotated upstream tag ref")
    tag = get_json(API + "/git/tags/" + TAG_OBJECT)
    if (tag.get("tag") != TAG or
        tag.get("object", {}).get("type") != "commit" or
        tag.get("object", {}).get("sha") != COMMIT):
        raise ValueError("Unexpected source tag target commit")
    decoded = {}
    for path, sha in expected.items():
        url = API + "/contents/" + path + "?ref=" + COMMIT
        row = get_json(url)
        if (row.get("path") != path or row.get("sha") != sha or
            row.get("encoding") != "base64" or
            type(row.get("content")) is not str):
            raise ValueError("Wrong source path/blob identity: " + path)
        try:
            data = base64.b64decode(row["content"], validate=False)
            if len(data) > 100_000 or git_blob_sha(data) != sha:
                raise ValueError("Source blob content mismatch: " + path)
            decoded[path] = data.decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise ValueError("Invalid source blob content: " + path) from exc
    license_text = " ".join(decoded["LICENSE.TXT"].split())
    require_markers(license_text, (" ".join(v.split()) for v in LICENSE_MARKERS.values()), "LICENSE.TXT")
    require_markers(decoded["COPYING"], ("GNU GENERAL PUBLIC LICENSE", "Version 2, June 1991"), "COPYING")
    require_markers(decoded["ci/winnie/package_postgis.sh"], PACKAGE_MARKERS, "package_postgis.sh")
    require_markers(decoded["ci/winnie/winnie_common.sh"], COMMON_MARKERS, "winnie_common.sh")
    return {
        "schemaVersion": "pgextwin-issue112-osgeo-tagged-source-rights-deny-only/v1",
        "scope": "TAGGED_SOURCE_REFERENCE_ONLY_NOT_ACTUAL_PRODUCER",
        "upstreamRepository": "postgis/postgis",
        "tag": TAG, "annotatedTagObject": TAG_OBJECT, "tagTargetCommit": COMMIT,
        "sourceBlobSha1": dict(sorted(expected.items())),
        "taggedSourceLicenseStatements": dict(sorted(LICENSE_MARKERS.items())),
        "winnieScriptsSourcePinned": True,
        "winnieBuildDependencyVersionOverridesPossible": True,
        "originalZip": {
            "name": "postgis-bundle-pg18-3.7.0x64.zip",
            "bytes": 83320975,
            "sha256": "fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40",
        },
        "originalZipProducerMatchedToTag": False,
        "originalZipProducerRunAndSignatureVerified": False,
        "exactBundledDllLicenseAttributionVerified": False,
        "allComponentNoticesDeliveredVerified": False,
        "actualWindowsDependencyClosureVerified": False,
        "newScopedOwnerSignedAdmission": False,
        "publicGetAuthorized": False,
        "mirrorAuthorized": False,
        "releaseAuthorized": False,
        "publisherAuthorized": False,
    }

def main():
    print(json.dumps(audit(), ensure_ascii=True, sort_keys=True))
    print("POSTGIS_TAGGED_SOURCE_RIGHTS=OBSERVED EXACT_BINARY_PROVENANCE=UNVERIFIED "
          "DLL_RIGHTS_CLOSURE=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")

if __name__ == "__main__":
    main()
