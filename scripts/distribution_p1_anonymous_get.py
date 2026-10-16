#!/usr/bin/env python3
"""Issue #112: anonymous GET-only original Release/attestation snapshot helper.

This tool is a data transport, NOT an authentication/approval decision. Never
promotes a fetched SHA or a PACKAGE-INFO field into trusted source evidence.
All inputs must be independently reconciled against the pinned P1 Policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

from distribution_manifest_v1 import Denied, require, strict_json

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
MAX_JSON = 8 * 1024 * 1024
MAX_ZIP = 64 * 1024 * 1024
MAX_BUNDLES = 30


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


_OPENER = build_opener(_NoRedirect())


def _allowed(url, kind):
    try:
        u = urlsplit(url)
        host = (u.hostname or "").lower()
        require(u.scheme == "https" and not u.username and not u.password
                and not u.fragment and u.port in (None, 443),
                "unsafe URL scheme/authority")
        if kind == "api":
            require(host == "api.github.com" and u.path.startswith("/repos/pgextwin/"),
                    "unauthorized API origin")
        elif kind == "asset":
            require(host in ("api.github.com", "release-assets.githubusercontent.com",
                             "objects.githubusercontent.com", "github.com"),
                    "unapproved Release asset redirect")
        elif kind == "bundle":
            require(host == "api.github.com" or
                    (host.endswith(".blob.core.windows.net")
                     and host != ".blob.core.windows.net"),
                    "unapproved Attestation bundle origin")
        else:
            raise Denied("unknown request origin class")
    except ValueError as exc:
        raise Denied("invalid URL authority") from exc
    return url


def _response(url, *, kind, accept, limit, expected_size=None):
    """Return bytes via bounded no-redirect HTTP GET. No auth header or cookies."""
    require(type(limit) is int and 0 < limit <= MAX_ZIP, "invalid byte budget")
    for hop in range(4):
        _allowed(url, kind)
        headers = {"Accept": accept, "User-Agent": "pgextwin-p1-anonymous-get/1",
                   "X-GitHub-Api-Version": "2022-11-28"}
        request = Request(url, headers=headers, method="GET")
        try:
            resp = _OPENER.open(request, timeout=30)
        except HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                location = exc.headers.get("Location")
                exc.close()
                require(type(location) is str and bool(location),
                        "missing redirect Location")
                url = urljoin(url, location)
                # A metadata API must never redirect to a different origin.
                if kind == "api":
                    require(urlsplit(url).hostname == "api.github.com",
                            "API metadata redirected to other origin")
                continue
            message = "GitHub GET HTTP " + str(exc.code)
            exc.close()
            raise Denied(message) from exc
        except (OSError, URLError) as exc:
            raise Denied("anonymous GET network failure") from exc
        try:
            require(resp.status == 200 and not resp.headers.get("Content-Range"),
                    "partial/unexpected HTTP GET response")
            length = resp.headers.get("Content-Length")
            if length is not None:
                require(length.isascii() and length.isdecimal()
                        and int(length) <= limit, "oversized HTTP Content-Length")
            data = bytearray()
            while True:
                block = resp.read(min(1024 * 1024, limit - len(data) + 1))
                if not block:
                    break
                data.extend(block)
                require(len(data) <= limit, "GET exceeded maximum byte limit")
            if length is not None:
                require(int(length) == len(data), "truncated HTTP body")
            if expected_size is not None:
                require(len(data) == expected_size, "Release Asset size mismatch")
            return bytes(data)
        finally:
            resp.close()
    raise Denied("excessive HTTP redirect chain")


def _api(path):
    require(re.fullmatch(
        r"repos/pgextwin/[a-z][a-z0-9_]*(?:/releases/[1-9][0-9]*|"
        r"/attestations/sha256:[0-9a-f]{64})?", path), "nonallowlisted API path")
    data = _response("https://api.github.com/" + path, kind="api",
                     accept="application/vnd.github+json", limit=MAX_JSON)
    obj = strict_json(data)
    require(type(obj) is dict, "unexpected API JSON")
    return obj


def _safe_dir(directory):
    require(directory.is_dir() and not directory.is_symlink(),
            "destination must be an existing real directory")
    require(not any(p.is_symlink() for p in directory.parents if p.exists()),
            "symlink ancestor in destination")
    return directory


def _create_no_overwrite(directory, filename, data):
    require(ASSET_NAME.fullmatch(filename) and filename not in (".", ".."),
            "unsafe output filename")
    _safe_dir(directory)
    target = directory / filename
    require(not target.exists() and not target.is_symlink(), "output already exists")
    fd, tmp = tempfile.mkstemp(prefix=".p1-get-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Fail closed if a competing actor inserted the destination.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        dest_fd = os.open(target, flags, 0o600)
        try:
            with os.fdopen(dest_fd, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            target.unlink(missing_ok=True)
            raise
        return target
    finally:
        Path(tmp).unlink(missing_ok=True)


def acquire(name, *, repo_id, release_id, asset_id, asset_sha,
            asset_size, target_sha, tag, destination):
    """One immutable-identity-pinned original ZIP and associated API bundles."""
    require(NAME.fullmatch(name) and HEX40.fullmatch(target_sha)
            and HEX64.fullmatch(asset_sha) and TAG.fullmatch(tag),
            "missing immutable identifiers")
    require(all(type(n) is int and n > 0 for n in
                (repo_id, release_id, asset_id, asset_size))
            and asset_size <= MAX_ZIP, "invalid numeric pins/size")
    _safe_dir(destination)
    metadata = _api("repos/pgextwin/" + name)
    require(metadata.get("id") == repo_id and metadata.get("full_name") ==
            "pgextwin/" + name, "repo numeric identity mismatch")
    release = _api("repos/pgextwin/" + name + "/releases/" + str(release_id))
    require(release.get("id") == release_id and release.get("tag_name") == tag
            and release.get("target_commitish") == target_sha
            and release.get("draft") is False and release.get("prerelease") is False,
            "original Release identity/commit mismatch")
    assets = release.get("assets")
    require(type(assets) is list and len({a.get("id") for a in assets
            if type(a) is dict}) == len(assets), "duplicate/invalid Release assets")
    selected = [a for a in assets if a.get("id") == asset_id]
    require(len(selected) == 1, "missing original numeric Asset ID")
    item = selected[0]
    filename = item.get("name")
    require(type(filename) is str and ASSET_NAME.fullmatch(filename)
            and filename.endswith(".zip") and item.get("size") == asset_size
            and item.get("state") == "uploaded"
            and item.get("digest") == "sha256:" + asset_sha
            and item.get("browser_download_url") ==
            f"https://github.com/pgextwin/{name}/releases/download/{tag}/{filename}",
            "original ZIP Asset name/digest/size/URL mismatch")
    data = _response(
        f"https://api.github.com/repos/pgextwin/{name}/releases/assets/{asset_id}",
        kind="asset", accept="application/octet-stream", limit=MAX_ZIP,
        expected_size=asset_size)
    require(hashlib.sha256(data).hexdigest() == asset_sha,
            "original Release ZIP SHA256 mismatch")
    attestations = _api(
        "repos/pgextwin/" + name + "/attestations/sha256:" + asset_sha)
    rows = attestations.get("attestations")
    require(type(rows) is list and 0 < len(rows) <= MAX_BUNDLES,
            "missing/oversized public Attestation listing")
    bundles = []
    for row in rows:
        require(type(row) is dict and row.get("repository_id") == repo_id,
                "Attestation repository ID mismatch")
        bundle = row.get("bundle")
        if bundle is None:
            raw_url = row.get("bundle_url")
            require(type(raw_url) is str, "no Attestation bundle or URL")
            _allowed(raw_url, "bundle")
            raw = _response(raw_url, kind="bundle",
                            accept="application/json", limit=MAX_JSON)
            bundle = strict_json(raw)
        require(type(bundle) is dict and
                type(bundle.get("dsseEnvelope")) is dict and
                type(bundle.get("verificationMaterial")) is dict,
                "malformed public Sigstore bundle")
        bundles.append(json.dumps({"bundle": bundle}, sort_keys=True,
                                  separators=(",", ":")))
    require(len(set(bundles)) == len(bundles), "duplicate Attestation bundles")
    jsonl = ("\n".join(sorted(bundles)) + "\n").encode("utf-8")
    require(len(jsonl) <= MAX_JSON, "oversized Attestation bundle listing")
    _create_no_overwrite(destination, filename, data)
    bundle_path = _create_no_overwrite(
        destination, filename + ".jsonl", jsonl)
    return {"asset": filename, "assetSha256": asset_sha,
            "bundleFile": bundle_path.name,
            "bundleSha256": hashlib.sha256(jsonl).hexdigest(),
            "verificationLevel": "UNVERIFIED", "publicationAuthorized": False}


def main(argv=None):
    p = argparse.ArgumentParser(description="GET-only historical P1 transport")
    p.add_argument("--repo", required=True)
    p.add_argument("--repo-id", type=int, required=True)
    p.add_argument("--release-id", type=int, required=True)
    p.add_argument("--asset-id", type=int, required=True)
    p.add_argument("--asset-sha256", required=True)
    p.add_argument("--asset-size", type=int, required=True)
    p.add_argument("--target-sha", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        report = acquire(args.repo, repo_id=args.repo_id,
                         release_id=args.release_id, asset_id=args.asset_id,
                         asset_sha=args.asset_sha256, asset_size=args.asset_size,
                         target_sha=args.target_sha, tag=args.tag,
                         destination=args.output_dir)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"verificationLevel": "UNVERIFIED",
                          "publicationAuthorized": False, "decision": "DENY",
                          "reason": str(exc)[:180]}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
