#!/usr/bin/env python3
"""Read-only, authenticated GitHub Release discovery for allowlisted Windows providers.

All returned data are UNVERIFIED metadata. Never update a trusted feed or
download/extract/execute a binary, sign, mirror, or authorize publication.
"""
import argparse
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = ROOT / "external/discovery-providers-v1.json"
BASELINES = (
    ROOT / "evidence/issue112-external-release-inventory-20261103.json",
    ROOT / "evidence/issue112-external-provider-portalcorp-20261103.json",
)
MAX_PAGES = 40
MAX_PAGE_BYTES = 5_000_000
REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
NAME_RE = re.compile(r"[A-Za-z0-9._+-]+\Z")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("Unexpected GitHub API redirect")


def config_providers(document):
    if (document.get("schemaVersion") != "pgextwin-external-discovery-providers/v1"
            or document.get("trust") != "READ_ONLY_METADATA_NEVER_AUTHORIZE"
            or document.get("githubApiHost") != "api.github.com"):
        raise ValueError("Discovery config trust boundary mismatch")
    providers = document.get("providers")
    if not isinstance(providers, list) or not 1 <= len(providers) <= 24:
        raise ValueError("Invalid provider count")
    seen = set()
    for p in providers:
        if (not isinstance(p, dict) or set(p) !=
                {"repo", "providerType", "extension", "assetPattern"}
                or not REPO_RE.fullmatch(p["repo"])
                or not re.fullmatch(r"[a-z][a-z0-9_]*", p["extension"])
                or p["providerType"] not in ("upstream-official", "community", "vendor")
                or p["repo"].lower() in seen):
            raise ValueError("Invalid or duplicate provider")
        seen.add(p["repo"].lower())
        pattern = p["assetPattern"]
        if not isinstance(pattern, str) or len(pattern) > 160 or not pattern.startswith("^") or not pattern.endswith("$"):
            raise ValueError("Invalid filename allowlist")
        re.compile(pattern)
    return providers


def fetch_release_page(repo, page, token):
    if not REPO_RE.fullmatch(repo) or not 1 <= page <= MAX_PAGES:
        raise ValueError("Untrusted repository/page")
    url = f"https://api.github.com/repos/{repo}/releases?per_page=100&page={page}"
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "pgextwin-readonly-external-discovery/1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(urllib.request.Request(url, headers=headers), timeout=35) as response:
        if response.status != 200 or response.url != url:
            raise ValueError("Unexpected GitHub API endpoint")
        payload = response.read(MAX_PAGE_BYTES + 1)
    if len(payload) > MAX_PAGE_BYTES:
        raise ValueError("Release API page too large")
    result = json.loads(payload)
    if not isinstance(result, list) or len(result) > 100:
        raise ValueError("Invalid release API response")
    return result


def summarize_pages(provider, pages):
    repo = provider["repo"]
    pattern = re.compile(provider["assetPattern"])
    seen_releases, seen_assets = set(), set()
    releases = []
    if not pages or pages[-1] != []:
        raise ValueError("Full-page inventory requires empty terminal page")
    for page in pages[:-1]:
        if not isinstance(page, list) or not page or len(page) > 100:
            raise ValueError("Release page gap/overflow")
        for release in page:
            rid, tag = release["id"], release["tag_name"]
            if (not isinstance(rid, int) or rid <= 0 or rid in seen_releases
                    or not isinstance(tag, str) or not tag or "/" in tag or len(tag) > 128
                    or release.get("draft") is not False
                    or not isinstance(release.get("prerelease"), bool)):
                raise ValueError("Invalid, duplicate or draft Release")
            seen_releases.add(rid)
            raw_assets = release.get("assets")
            if not isinstance(raw_assets, list) or len(raw_assets) > 300:
                raise ValueError("Invalid release assets")
            windows = []
            for asset in raw_assets:
                name = asset.get("name")
                if not isinstance(name, str) or not NAME_RE.fullmatch(name):
                    raise ValueError("Unsafe Release asset filename")
                if not pattern.fullmatch(name):
                    continue
                aid, size, digest = asset["id"], asset["size"], asset.get("digest")
                url = asset["browser_download_url"]
                expected_prefix = f"https://github.com/{repo}/releases/download/"
                parsed = urllib.parse.urlsplit(url)
                if (not isinstance(aid, int) or aid <= 0 or aid in seen_assets
                        or not isinstance(size, int) or not 0 < size <= 2_000_000_000
                        or (digest is not None and
                            (not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest)))
                        or not url.startswith(expected_prefix)
                        or parsed.scheme != "https" or parsed.hostname != "github.com"
                        or parsed.username is not None or parsed.password is not None
                        or parsed.port not in (None, 443)
                        or asset.get("state") != "uploaded"):
                    raise ValueError("Untrusted Windows asset identity")
                seen_assets.add(aid)
                windows.append({"assetId": aid, "name": name, "size": size,
                                "digest": digest, "url": url, "state": "uploaded"})
            releases.append({
                "releaseId": rid, "tag": tag, "publishedAt": release.get("published_at"),
                "draft": False, "prerelease": release["prerelease"],
                "assetCount": len(raw_assets),
                "windowsAssets": sorted(windows, key=lambda a: a["assetId"]),
            })
    return {"repo": repo, "providerType": provider["providerType"],
            "pagesScanned": len(pages), "releasesSeen": len(releases),
            "releasesWithWindowsAssets": sum(bool(r["windowsAssets"]) for r in releases),
            "windowsAssets": len(seen_assets),
            "windowsAssetsMissingDigest": sum(
                a["digest"] is None for r in releases for a in r["windowsAssets"]),
            "releases": releases}


def scan(providers, fetch):
    results = []
    for provider in providers:
        pages = []
        for i in range(1, MAX_PAGES + 1):
            page = fetch(provider["repo"], i)
            pages.append(page)
            if not page:
                break
        else:
            raise ValueError("Page limit reached without terminal empty page")
        results.append(summarize_pages(provider, pages))
    return {"schemaVersion": "pgextwin-external-windows-release-inventory/v1",
            "trust": "UNVERIFIED_METADATA_ONLY",
            "publicationAuthorized": False,
            "redistributionAuthorized": False,
            "repositories": results}


def inventory_assets(inventory):
    assets = {}
    for repository in inventory["repositories"]:
        repo = repository["repo"]
        for release in repository["releases"]:
            for asset in release["windowsAssets"]:
                key = (repo.lower(), release["releaseId"], asset["assetId"])
                if key in assets:
                    raise ValueError("Duplicate Release/asset identity in inventory")
                assets[key] = (release["tag"], asset["name"], asset["size"],
                               asset["digest"], asset["url"], asset["state"])
    return assets


def compare(scan_result, baselines):
    old = inventory_assets({"repositories": [
        repository for inventory in baselines for repository in inventory["repositories"]]})
    current = inventory_assets(scan_result)
    return {"new": len(current.keys() - old.keys()),
            "missing": len(old.keys() - current.keys()),
            "changed": sum(old[key] != current[key] for key in old.keys() & current.keys()),
            "unchanged": sum(old[key] == current[key] for key in old.keys() & current.keys())}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    providers = config_providers(json.loads(PROVIDERS.read_text(encoding="utf-8")))
    token = os.environ.get("GITHUB_TOKEN", "")
    results = scan(providers, lambda repo, page: fetch_release_page(repo, page, token))
    baselines = [json.loads(path.read_text(encoding="utf-8")) for path in BASELINES]
    delta = compare(results, baselines)
    report = {**results, "deltaFromPinnedBaselines": delta}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"repos": len(providers),
                      "releases": sum(x["releasesSeen"] for x in results["repositories"]),
                      "windowsAssets": sum(x["windowsAssets"] for x in results["repositories"]),
                      "missingApiDigests": sum(x["windowsAssetsMissingDigest"] for x in results["repositories"]),
                      "delta": delta,
                      "downloadAuthorized": False, "mirrorAuthorized": False}, sort_keys=True))
    with open(os.environ.get("GITHUB_STEP_SUMMARY", os.devnull), "a", encoding="utf-8") as out:
        out.write("## External Windows discovery (nonpublishing)\n")
        out.write(f"Providers: {len(providers)}; delta: {delta}\n\n")
        out.write("All candidates remain **UNVERIFIED / DOWNLOAD DENY / MIRROR DENY**.\n")


if __name__ == "__main__":
    main()
