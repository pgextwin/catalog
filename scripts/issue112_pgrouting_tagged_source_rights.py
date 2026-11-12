#!/usr/bin/env python3
"""Pinned pgRouting v4.0.0 source license/Boost observations, DENY-only.

This is NOT an OSGeo producer attestation or DLL-specific rights admission.
All network reads are exact upstream GitHub API GETs; no binary or ZIP is fetched.
"""
import base64
import json
import os
import re
import urllib.request

from issue112_osgeo_tagged_source_rights import RejectRedirect, git_blob_sha

API = "https://api.github.com/repos/pgRouting/pgrouting"
TAG = "v4.0.0"
TAG_OBJECT = "83985fc60ec73355cc9bd8b59080a4c42dc6ad6b"
COMMIT = "4f0eec583f0c9e6a82a5b3356ff300029d11ed53"
BLOBS = {
    "LICENSE": "d159169d1050894d3ea3b98e1c965c4058208fe1",
    "BOOST_LICENSE_1_0.txt": "36b7cd93cdfbac762f5be4c6ce276df2ea6305c2",
    "README.md": "1f563b4b009fe77c31f578b7de05fd1934163eb7",
    "CMakeLists.txt": "b7b00200696c8045869a36d4f2fddc2c1ead9427",
}
# The Windows PG18 SQL receipt reported pgRouting 4.0.1, whereas the
# previous source-only audit fixed the earlier v4.0.0 tag. Verify both without
# assuming that either source revision produced the observed DLL.
TAG_401 = "v4.0.1"
TAG_OBJECT_401 = "b817fb3d9d641fb5c65c8ab1d855b398c6983677"
COMMIT_401 = "8988eebdff0e01327c9d48fe7c80b437dc9bc992"
BLOBS_401 = {**BLOBS, "CMakeLists.txt": "547997f8085c45e9c478d6a2632a3c0c13668cbd"}

SOURCE_MARKERS = {
    "LICENSE": (
        "GNU GENERAL PUBLIC LICENSE", "Version 2, June 1991",
    ),
    "BOOST_LICENSE_1_0.txt": (
        "Boost Software License - Version 1.0",
        "The copyright notices in the Software",
    ),
    "README.md": (
        "Most features are available under [GPL-2.0-or-later]",
        "Some Boost extensions are available under Boost license",
        "Some code contributed by iMaptools.com is available under MIT-X license.",
        "pre-built Windows binaries can be downloaded from https://postgis.net/windows_downloads",
    ),
    "CMakeLists.txt": (
        "project(PGROUTING VERSION 4.0.0",
        "find_package(Boost ",
        "set(PROJECT_LIB_NAME ",
    ),
}
MAX_RESPONSE = 256_000
MAX_SOURCE_FILE = 128_000
SOURCE_SCOPE = "PINNED_PGROUTING_SOURCE_ONLY_NOT_OSGEO_DLL_PRODUCER"


def source_get_json(url):
    if not url.startswith(API + "/") or len(url) > 300:
        raise ValueError("Unauthorized source endpoint")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "pgextwin-issue112-pgrouting-source-rights-deny-only",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    opener = urllib.request.build_opener(RejectRedirect())
    with opener.open(urllib.request.Request(url, headers=headers), timeout=15) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError("Unexpected source response or redirect")
        content = response.read(MAX_RESPONSE + 1)
    if len(content) > MAX_RESPONSE:
        raise ValueError("Source response exceeds bound")
    return json.loads(content.decode("utf-8"))


def audit(get_json=source_get_json, expected_blobs=None, *, release_tag=TAG):
    """Check one immutable source tag. Neither tag grants binary attribution."""
    if release_tag not in (TAG, TAG_401):
        raise ValueError("Unrecognized pgRouting release tag")
    current = release_tag == TAG_401
    tag_object = TAG_OBJECT_401 if current else TAG_OBJECT
    commit = COMMIT_401 if current else COMMIT
    trusted_blobs = BLOBS_401 if current else BLOBS
    # Only the synthetic offline tests replace these SHA-1 pins.
    expected = trusted_blobs if expected_blobs is None else expected_blobs
    if (set(expected) != set(trusted_blobs)
            or any(not isinstance(x, str) or not re.fullmatch("[0-9a-f]{40}", x)
                   for x in expected.values())):
        raise ValueError("Untrusted or incomplete pinned source inventory")
    ref = get_json(API + "/git/ref/tags/" + release_tag)
    if ref.get("ref") != "refs/tags/" + release_tag or ref.get("object") != {
            "sha": tag_object, "type": "tag", "url": API + "/git/tags/" + tag_object}:
        raise ValueError("Unverified annotated pgRouting tag ref")
    tagged = get_json(API + "/git/tags/" + tag_object)
    if (tagged.get("tag") != release_tag
            or tagged.get("object", {}).get("type") != "commit"
            or tagged.get("object", {}).get("sha") != commit):
        raise ValueError("Unverified pgRouting tag-to-commit mapping")

    for path, sha in sorted(expected.items()):
        row = get_json(API + "/contents/" + path + "?ref=" + commit)
        if (row.get("path") != path or row.get("sha") != sha
                or row.get("encoding") != "base64"
                or type(row.get("content")) is not str):
            raise ValueError("Wrong source path/blob: " + path)
        try:
            data = base64.b64decode(row["content"], validate=False)
            if not 0 < len(data) <= MAX_SOURCE_FILE or git_blob_sha(data) != sha:
                raise ValueError("Source bytes do not match pinned Git blob: " + path)
            source = data.decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise ValueError("Invalid pinned pgRouting source: " + path) from exc
        normalized = " ".join(source.split())
        markers = SOURCE_MARKERS[path]
        if current and path == "CMakeLists.txt":
            markers = tuple(x.replace("VERSION 4.0.0", "VERSION 4.0.1")
                            for x in markers)
        for phrase in markers:
            if " ".join(phrase.split()) not in normalized:
                raise ValueError("Source license/build claim absent: " + path + " / " + phrase)

    return {
        "schemaVersion": "pgextwin-issue112-pgrouting-tagged-source-rights-deny-only/v1",
        "scope": SOURCE_SCOPE,
        "sourceRepository": "pgRouting/pgrouting",
        "tag": release_tag, "annotatedTagObject": tag_object, "tagCommit": commit,
        "sourceGitBlobsSha1": dict(sorted(expected.items())),
        "licenseObservations": {
            "projectREADME": "most features GPL-2.0-or-later, not every compiled component",
            "projectLicense": "GPL-2.0 full text",
            "boost": "Boost-1.0 full text, project README notes some Boost extensions",
            "iMaptools": "README mentions MIT-X code; exact file-specific notice not yet pinned",
        },
        "candidateOsgeoZip": {
            "name": "postgis-bundle-pg18-3.7.0x64.zip",
            "bytes": 83320975,
            "sha256": "fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40",
            "dllBasename": "libpgrouting-4.0.dll",
            "observedInstalledVersionFromPriorWindowsSql": "4.0.1",
        },
        "upstreamTagSignatureVerified": False,
        "candidateDllBuiltFromThisTagVerified": False,
        "candidateDllPerFileSourceAndLicenseClosureVerified": False,
        "candidateDllBoostAndImaptoolsNoticeClosureVerified": False,
        "upstreamProducerSignedExactZipProvenanceVerified": False,
        "windowsDependencyClosureVerified": False,
        "newScopedOwnerSignedAdmissionVerified": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "releaseAuthorized": False, "publisherAuthorized": False,
    }


def main():
    receipts = [audit(release_tag=tag) for tag in (TAG, TAG_401)]
    print(json.dumps({"sourceOnlyReceipts": receipts}, sort_keys=True, ensure_ascii=True))
    print("PGROUTING_SOURCE_RIGHTS=OBSERVED ORIGINAL_DLL_LINK=UNVERIFIED "
          "NOTICE_CLOSURE=UNVERIFIED PRODUCER=UNVERIFIED GET=DENY "
          "MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
