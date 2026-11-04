#!/usr/bin/env python3
"""Read-only original GitHub ZIP byte pilot for Issue #112.

Only independently rehash and inspect two public third-party ZIPs.
No extraction, execution, mirroring, publication, signature trust or install.
"""
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


def run():
    opener = urllib.request.build_opener(PinnedRedirects())
    for item in SOURCES:
        url = safe_url("https://github.com/" + item["repo"] +
                       "/releases/download/" + item["tag"] + "/" + item["asset"])
        request = urllib.request.Request(url, headers={"User-Agent": "pgextwin-issue112-readonly-pilot/1"})
        with opener.open(request, timeout=45) as resp:
            safe_url(resp.url)
            data = resp.read(MAX_BYTES + 1)
        if len(data) != item["bytes"] or len(data) > MAX_BYTES:
            raise ValueError(item["name"] + ": source ZIP size mismatch")
        digest = hashlib.sha256(data).hexdigest()
        if digest != item["sha256"]:
            raise ValueError(item["name"] + ": original ZIP SHA256 mismatch")
        zip_info = audit_zip(data)
        print(json.dumps({
            "pilot": item["name"], "result": "ORIGINAL_ZIP_SHA256_AND_CRC_PASS",
            "releaseId": item["releaseId"], "assetId": item["assetId"],
            "size": len(data), "sha256": digest, **zip_info,
            "signatureVerified": False, "provenanceVerified": False,
            "licenseApproved": False, "abiApproved": False,
            "downloadAuthorized": False, "mirrorAuthorized": False,
        }, sort_keys=True))
    print("PASS: two read-only original-byte pilots; FORMAL_DISTRIBUTION=DENY")


if __name__ == "__main__":
    run()
