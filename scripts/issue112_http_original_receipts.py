#!/usr/bin/env python3
"""Nonpublishing original-byte observations of pgsql-http Windows community ZIPs.

No signed admission, public GET, source-to-binary attestation, mirroring,
third-party license clearance or archive upload is authorized by this script.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import tempfile
import urllib.request
import zipfile

ORIGIN = "https://www.postgresonline.com/downloads/"
# Publisher version claims; do not treat as independently verified.
CANDIDATES = {
    "14": ("pg14http_w64.zip", "1.5.0"),
    "15": ("pg15http_w64.zip", "1.6.1"),
    "16": ("pg16http_w64.zip", "1.6.1"),
    "17": ("pg17http_w64.zip", "1.7.1"),
    "18": ("pg18http_w64.zip", "1.7.1"),
}
MAX_ZIP = 64 * 1024 * 1024
MAX_MEMBERS = 2048
MAX_EXPANDED = 256 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024


class DenyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("Original origin redirect prohibited")


def copy_stream(stream, path, limit=MAX_ZIP):
    if limit < 22:
        raise ValueError("Invalid original byte cap")
    digest = hashlib.sha256()
    count = 0
    with Path(path).open("xb") as file:
        while chunk := stream.read(1024 * 1024):
            count += len(chunk)
            if count > limit:
                raise ValueError("Original ZIP exceeds hard size cap")
            digest.update(chunk)
            file.write(chunk)
    if count < 22:
        raise ValueError("Original ZIP too short")
    return count, digest.hexdigest()


def inspect_archive(path):
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if not 1 <= len(members) <= MAX_MEMBERS:
            raise ValueError("Unbounded ZIP member count")
        seen = set()
        total = 0
        files = []
        dlls = []
        notices = []
        for info in members:
            name = info.filename
            parts = name.rstrip("/").split("/")
            mode = (info.external_attr >> 16) & 0o170000
            if (not name or name.startswith("/") or "\\" in name or
                    ":" in name or "\x00" in name or
                    any(part in ("", ".", "..") for part in parts) or
                    mode == 0o120000 or info.flag_bits & 1):
                raise ValueError("Unsafe original ZIP path or member")
            lower = name.rstrip("/").casefold()
            if lower in seen:
                raise ValueError("Duplicate casefold ZIP member")
            seen.add(lower)
            if info.is_dir():
                continue
            if (info.file_size < 0 or info.file_size > MAX_MEMBER or
                    info.compress_size < 0 or
                    info.file_size > 400 * max(1, info.compress_size)):
                raise ValueError("Overexpanded ZIP member")
            total += info.file_size
            if total > MAX_EXPANDED:
                raise ValueError("ZIP expanded budget exceeded")
            files.append(name)
            if lower.endswith(".dll"):
                dlls.append(name)
            if re.search(r"(?:^|[._-])(license|licence|copying|notice|copyright)(?:$|[._-])",
                         PurePosixPath(name).name, re.I):
                notices.append(name)
        if not any(PurePosixPath(name).name.lower() == "http.control" for name in files):
            raise ValueError("Missing http.control")
        main = [name for name in dlls
                if PurePosixPath(name).name.lower() == "http.dll"]
        if len(main) != 1:
            raise ValueError("Exactly one http.dll required")
        with archive.open(main[0]) as data:
            pe = data.read(4096)
        if len(pe) < 128 or pe[:2] != b"MZ":
            raise ValueError("Missing http.dll PE signature")
        offset = struct.unpack_from("<I", pe, 0x3c)[0]
        if (offset + 6 > len(pe) or pe[offset:offset + 4] != b"PE\0\0" or
                struct.unpack_from("<H", pe, offset + 4)[0] != 0x8664):
            raise ValueError("http.dll is not verified AMD64 PE")
        bad = archive.testzip()
        if bad is not None:
            raise ValueError("ZIP CRC rejected: " + bad)
    return {
        "zipMemberCount": len(members),
        "declaredExpandedBytes": total,
        "httpDllPath": main[0],
        "dllMemberPaths": sorted(dlls),
        "rightsNamedPaths": sorted(notices),
        "amd64PeHeaderVerified": True,
        "zipCrcVerified": True,
    }


def observe(pg):
    if pg not in CANDIDATES:
        raise ValueError("Unsupported PostgreSQL major")
    name, advertised_version = CANDIDATES[pg]
    url = ORIGIN + name
    request = urllib.request.Request(
        url, headers={"User-Agent": "pgextwin-issue112-candidate-research/1"})
    with tempfile.TemporaryDirectory(prefix="issue112-http-") as tmp:
        dest = Path(tmp) / name
        with urllib.request.build_opener(DenyRedirect).open(request, timeout=60) as response:
            if response.status != 200 or response.geturl() != url:
                raise ValueError("Source origin, HTTP status or URL mismatch")
            media = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
            if media in {"text/html", "text/plain", "application/json"}:
                raise ValueError("Non-ZIP HTTP response")
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_ZIP:
                raise ValueError("HTTP Content-Length exceeds research cap")
            size, sha = copy_stream(response, dest)
        observation = inspect_archive(dest)
    return {
        "schemaVersion": "pgextwin-http-original-observation-nonpublishing/v1",
        "pgMajor": pg, "originalProviderUrl": url,
        "publisherAdvertisedVersionNotVerified": advertised_version,
        "observedOriginalBytesUntrusted": size,
        "observedOriginalSha256Untrusted": sha,
        **observation,
        "sourceToBinaryProducerAttestationVerified": False,
        "allComponentLicensesAndNoticesVerified": False,
        "targetWindowsLoaderClosureVerified": False,
        "independentSignedAdmission": False,
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
        "redistributionAuthorized": False,
        "publisherAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pg", required=True, choices=tuple(CANDIDATES))
    args = parser.parse_args()
    print(json.dumps(observe(args.pg), sort_keys=True, ensure_ascii=True))
    print("HTTP_ORIGINAL_OBSERVED_ONLY=YES PUBLISHER_IDENTITY=UNVERIFIED "
          "RIGHTS=UNVERIFIED SOURCE_PROVENANCE=UNVERIFIED "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
