"""Shared projection of approved Catalog release inventory rows."""
import re

ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
LICENSE_URL = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
                         r"/blob/([0-9a-f]{40})/([A-Za-z0-9._/-]+)\Z")


def version_for(upstream, major):
    specific = upstream.get("perPostgresql", {}).get(major, {})
    return specific.get("version", upstream.get("version"))


def pinned_license_url(url):
    match = LICENSE_URL.fullmatch(url) if isinstance(url, str) else None
    return match and not any(p in ("", ".", "..") for p in match[3].split("/"))


def license_for(license_info):
    urls = license_info.get("evidenceUrls") if isinstance(license_info, dict) else None
    if (not isinstance(license_info, dict) or set(license_info) != {"name", "evidenceUrls"}
            or not isinstance(license_info["name"], str) or not license_info["name"].strip()
            or not isinstance(urls, list) or not urls
            or not all(pinned_license_url(url) for url in urls)):
        raise ValueError("Missing or invalid version-specific license evidence")
    return license_info


def license_pins(license_info):
    return [LICENSE_URL.fullmatch(url).groups() for url in license_for(license_info)["evidenceUrls"]]


def release_assets(repo, tag, release):
    release_id = release.get("id")
    if (not isinstance(tag, str) or not ASSET.fullmatch(tag) or
        type(release_id) is not int or release_id <= 0 or
        release.get("tag_name") != tag or release.get("draft") is not False or
        not isinstance(release.get("published_at"), str)):
        raise ValueError("Public Release identity mismatch")
    assets = {}
    used = set()
    for item in release["assets"]:
        asset = item["name"]
        ident = item["id"]
        if (not isinstance(asset, str) or not ASSET.fullmatch(asset) or
            type(ident) is not int or ident <= 0 or ident in used or
            asset in assets or item.get("state") != "uploaded" or
            item.get("browser_download_url") !=
                f"https://github.com/{repo}/releases/download/{tag}/{asset}"):
            raise ValueError("Unsafe, duplicate, or moved Release asset")
        used.add(ident)
        assets[asset] = item
    return release_id, assets


def match_zip(repo, tag, major, pg, assets):
    filename = pg["asset"]
    digest = pg["sha256"]
    name = repo.split("/", 1)[1]
    url = f"https://github.com/{repo}/releases/download/{tag}/{filename}"
    if (not isinstance(filename, str) or not ASSET.fullmatch(filename) or
        not filename.startswith(name + "-") or
        not filename.endswith(f"-pg{major}-windows-x64.zip") or
        not isinstance(digest, str) or not SHA64.fullmatch(digest) or
        pg.get("downloadUrl", url) != url or filename not in assets or
        assets[filename].get("digest") != "sha256:" + digest or
        ("assetId" in pg and (type(pg["assetId"]) is not int or
                             pg["assetId"] != assets[filename]["id"]))):
        raise ValueError("Catalog ZIP does not match public Release")
    return assets[filename]["id"]
