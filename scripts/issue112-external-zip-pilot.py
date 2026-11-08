#!/usr/bin/env python3
"""Read-only original GitHub ZIP byte pilot for Issue #112.

Only independently rehash and inspect two public third-party ZIPs.
No extraction, execution, mirroring, publication, signature trust or install.
"""
import argparse
import hashlib
import io
import json
import stat
import urllib.parse
import urllib.request
import zipfile

SOURCES = (
    {
        "name": "oracle_fdw-official-pg18",
        "repo": "laurenz/oracle_fdw",
        "tag": "ORACLE_FDW_2_9_0",
        "asset": "oracle_fdw-2.9.0-pg18-win64.zip",
        "releaseId": 335861225,
        "assetId": 442625860,
        "bytes": 365101,
        "sha256": "ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678",
    },
    {
        "name": "pgvector-community-pg18",
        "repo": "andreiramani/pgvector_pgsql_windows",
        "tag": "0.8.7",
        "asset": "vector.v0.8.7-pg18.zip",
        "releaseId": 419235203,
        "assetId": 661612613,
        "bytes": 174796,
        "sha256": "7c4ae0e2b2cb1e547779209a34a7d3f05b82fd7912818bf3d7042266eda87e7d",
    },
)
# The source publishes no API digest. A prior genuine private PR CI observed
# the SHA256 below; this revision verifies it again against original bytes.
# An exact hash is integrity evidence, NOT authorization or provenance.
PORTALCORP = {
    "name": "portalcorp-pgvector-pg16",
    "repo": "portalcorp/pgvector_compiled",
    "tag": "v0.16.105",
    "asset": "pgvector-x86_64-pc-windows-msvc-pg16.zip",
    "releaseId": 182821763,
    "assetId": 203009337,
    "bytes": 163732,
    "sha256": "a9c63a3e51c09c18f192277a28be3fb021f3872a7cc2d23e4ca06e10f2c99571",
}
SOURCES += (PORTALCORP,)

ALLOWED_HOSTS = {
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
}
MAX_BYTES = 2_000_000
MAX_EXPANDED_BYTES = 10_000_000


def safe_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or
            parsed.username is not None or parsed.password is not None or
            parsed.port not in (None, 443)):
        raise ValueError("Untrusted release transport endpoint")
    return url


class PinnedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        safe_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def audit_zip(contents, *, max_members=200, max_expanded_bytes=MAX_EXPANDED_BYTES):
    with zipfile.ZipFile(io.BytesIO(contents)) as z:
        infos = z.infolist()
        if not infos or len(infos) > max_members:
            raise ValueError("Invalid ZIP member count")
        names = set()
        total = 0
        for entry in infos:
            name = entry.filename
            if (not name or name.startswith(("/", "\\")) or "\\" in name or
                    ":" in name or any(segment in ("", ".", "..") for segment in
                                        name.rstrip("/").split("/")) or
                    name.casefold() in names):
                raise ValueError("Unsafe ZIP entry path or duplicate")
            names.add(name.casefold())
            if stat.S_ISLNK(entry.external_attr >> 16):
                raise ValueError("ZIP symlink prohibited")
            total += entry.file_size
            if (total > max_expanded_bytes or
                    entry.file_size > max(entry.compress_size, 1) * 200):
                raise ValueError("ZIP expansion budget exceeded")
        if not any(name.endswith(".dll") for name in names):
            raise ValueError("Expected Windows DLL absent")
        if z.testzip() is not None:
            raise ValueError("ZIP member CRC mismatch")
        return {"zipMembers": len(infos), "uncompressedBytes": total}


def verify_observation_identity(opener, item):
    """Match immutable release/asset IDs before observing an unpinned ZIP."""
    url = ("https://api.github.com/repos/" + item["repo"] +
           "/releases/tags/" + item["tag"])
    req = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json",
                      "User-Agent": "pgextwin-issue112-readonly-pilot/1"})
    with opener.open(req, timeout=40) as response:
        raw = response.read(512_001)
    if len(raw) > 512_000:
        raise ValueError("Provider metadata response oversized")
    release = json.loads(raw)
    matches = [asset for asset in release.get("assets", [])
               if asset.get("id") == item["assetId"]]
    if (release.get("id") != item["releaseId"] or
            release.get("tag_name") != item["tag"] or
            release.get("draft") is not False or
            release.get("prerelease") is not False or
            len(matches) != 1 or
            matches[0].get("name") != item["asset"] or
            matches[0].get("size") != item["bytes"] or
            matches[0].get("state") != "uploaded" or
            matches[0].get("digest") is not None):
        raise ValueError("Unpinned original provider release identity changed")


def run(source="all"):
    selected = SOURCES if source == "all" else tuple(
        item for item in SOURCES if item["name"] == source)
    if not selected:
        raise ValueError("Unsupported read-only ZIP pilot source")
    opener = urllib.request.build_opener(PinnedRedirects())
    for item in selected:
        if item["name"] == PORTALCORP["name"]:
            verify_observation_identity(opener, item)
        url = safe_url("https://github.com/" + item["repo"] +
                       "/releases/download/" + item["tag"] + "/" + item["asset"])
        request = urllib.request.Request(url, headers={"User-Agent": "pgextwin-issue112-readonly-pilot/1"})
        with opener.open(request, timeout=45) as resp:
            safe_url(resp.url)
            data = resp.read(MAX_BYTES + 1)
        if len(data) != item["bytes"] or len(data) > MAX_BYTES:
            raise ValueError(item["name"] + ": source ZIP size mismatch")
        digest = hashlib.sha256(data).hexdigest()
        if item["sha256"] is not None and digest != item["sha256"]:
            raise ValueError(item["name"] + ": original ZIP SHA256 mismatch")
        zip_info = audit_zip(data)
        print(json.dumps({
            "pilot": item["name"], "result": "ORIGINAL_ZIP_SHA256_AND_CRC_PASS",
            "releaseId": item["releaseId"], "assetId": item["assetId"],
            "size": len(data), "sha256": digest, **zip_info,
            "sha256Pinned": item["sha256"] is not None,
            "candidateOnlyObservation": item["name"] == PORTALCORP["name"],
            "signatureVerified": False, "provenanceVerified": False,
            "licenseApproved": False, "abiApproved": False,
            "downloadAuthorized": False, "mirrorAuthorized": False,
        }, sort_keys=True))
    print("PASS: bounded read-only original-byte inspection; "
          "CANDIDATE_ONLY_FOR_UNPINNED=YES FORMAL_DISTRIBUTION=DENY")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default="all",
                        choices=["all"] + [item["name"] for item in SOURCES])
    run(parser.parse_args().source)
