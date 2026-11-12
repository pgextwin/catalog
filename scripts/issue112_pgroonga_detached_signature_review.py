#!/usr/bin/env python3
"""Inspect immutable PGroonga 4.1.0 detached signature *assets*, DENY-only.

Validating metadata and parsing OpenPGP packets does NOT validate their cryptographic
signature or signer trust. Do not authorize GET, release, mirror, or Publisher.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request
from urllib.parse import urlsplit

API = "https://api.github.com/repos/pgroonga/pgroonga/releases/407467158"
URL = "https://github.com/pgroonga/pgroonga/releases/download/4.1.0/"
REPO = "pgroonga/pgroonga"
VERSION = "4.1.0"
RELEASE_ID = 407467158
# Upstream Release metadata for separate .asc assets: NEVER public admission.
SIDECARS = {
    "14": (623767713, 833, "367267907048b5b96e1cfa29c0a1bf59080bda57acc2addd8a48e59a7851a388"),
    "15": (623768460, 833, "7f0f117ffe80eb7b52660010fb61f94622f00bfb9716c0b288739aec42def8cc"),
    "16": (623768698, 833, "f8061a35041aa825f7567d4b9eab17d719a0d1c1e46d6191ee50ad88132e68c4"),
    "17": (623768909, 833, "91ee97904f09185d7e7f4cd3f3527a52492c75cb51b77c993c23bd21e3b5998b"),
    "18": (623769210, 833, "fe9d89b0295d03d37a1c44a5425e1c46721f0b283e50a8ad0cbab0972848e172"),
}
DENIED = {"producerDetachedSignatureCryptographicallyVerified": False,
          "trustedSignerFingerprintVerified": False,
          "signedSourceToBinaryBuildProvenanceVerified": False,
          "allComponentRightsNoticesVerified": False,
          "independentOwnerSignedAdmission": False, "publicGetAuthorized": False,
          "mirrorAuthorized": False, "releaseAuthorized": False,
          "publisherAuthorized": False}


def unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("Duplicate JSON key: " + k)
        result[k] = v
    return result


def strict_baseline(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > 100_000:
        raise ValueError("Missing or unsafe baseline")
    result = json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if (type(result) is not dict or
            result.get("schemaVersion") != "pgextwin-issue112-pgroonga-official-release-watch-baseline/v1" or
            result.get("trust") != "UNVERIFIED_METADATA_NEVER_AUTHORIZE" or
            result.get("sourceRepo") != REPO or result.get("releaseTag") != VERSION or
            result.get("releaseId") != RELEASE_ID or
            any(result.get(k) is not False for k in (
                "downloadAuthorized", "publicationAuthorized", "redistributionAuthorized"))):
        raise ValueError("Unapproved official baseline or permissions")
    rows = result.get("records")
    if type(rows) is not list or len(rows) != 5:
        raise ValueError("Incomplete original ZIP baseline")
    original = {}
    for row in rows:
        if type(row) is not dict:
            raise ValueError("Invalid original row")
        pg = row.get("pgMajor")
        if pg not in SIDECARS or pg in original:
            raise ValueError("Duplicate or unsupported PG major")
        original[pg] = row
    if set(original) != set(SIDECARS):
        raise ValueError("Incomplete PostgreSQL major coverage")
    return original


def validate_metadata(release, original):
    if (type(release) is not dict or release.get("id") != RELEASE_ID or
            release.get("tag_name") != VERSION or
            release.get("draft") is not False or
            release.get("prerelease") is not False):
        raise ValueError("Unexpected official Release identity")
    assets = release.get("assets")
    if type(assets) is not list or len(assets) > 200:
        raise ValueError("Missing or unbounded Release asset list")
    by_name, ids = {}, set()
    for asset in assets:
        if type(asset) is not dict or type(asset.get("name")) is not str or \
                type(asset.get("id")) is not int or asset["name"] in by_name or \
                asset["id"] in ids:
            raise ValueError("Duplicate, malformed or conflicting Release asset")
        by_name[asset["name"]] = asset
        ids.add(asset["id"])
    rows = []
    for pg, entry in sorted(original.items()):
        name = f"pgroonga-{VERSION}-postgresql-{pg}-x64.zip"
        for asset_name, identity, uploader in (
                (name, (entry["assetId"], entry["originalBytes"], entry["originalSha256"]), "github-actions[bot]"),
                (name + ".asc", SIDECARS[pg], "groonga-release")):
            a = by_name.get(asset_name)
            if (not a or type(a["size"]) is not int or
                    (a["id"], a["size"], a.get("digest")) !=
                    (identity[0], identity[1], "sha256:" + identity[2]) or
                    a.get("browser_download_url") != URL + asset_name or
                    a.get("uploader", {}).get("login") != uploader or
                    a.get("state") != "uploaded"):
                raise ValueError("Exact provider ZIP/signature metadata changed: " + asset_name)
        rows.append({"pgMajor": pg, "zipAssetId": entry["assetId"],
                     "zipOriginalSha256": entry["originalSha256"],
                     "signatureAssetId": SIDECARS[pg][0],
                     "signatureBytes": SIDECARS[pg][1],
                     "signatureAssetSha256": SIDECARS[pg][2],
                     "signatureUploader": "groonga-release",
                     "signaturePacketsOnlyNotVerified": True})
    return rows


def github_release():
    req = urllib.request.Request(API, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "pgextwin-issue112-deny-only-signature-asset-intake/1",
        "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(req, timeout=15) as response:
        if response.geturl() != API or response.status != 200:
            raise ValueError("Unexpected Release API response")
        raw = response.read(500_001)
    if len(raw) > 500_000:
        raise ValueError("Unbounded provider metadata")
    return json.loads(raw, object_pairs_hook=unique)


def inspect_armored_signature(pg, fetch=None):
    """Read exact .asc bytes and parse a signer *hint*; no trust is established."""
    if pg not in SIDECARS:
        raise ValueError("Unsupported PostgreSQL major")
    name = f"pgroonga-{VERSION}-postgresql-{pg}-x64.zip.asc"
    original_url = URL + name
    if fetch is None:
        def fetch():
            req = urllib.request.Request(original_url, headers={
                "User-Agent": "pgextwin-issue112-deny-only-signature-asset-intake/1"})
            with urllib.request.urlopen(req, timeout=30) as response:
                resolved = urlsplit(response.geturl())
                if (resolved.scheme != "https" or resolved.hostname not in (
                    "github.com", "release-assets.githubusercontent.com",
                    "objects.githubusercontent.com")):
                    raise ValueError("Signature download redirect outside approved host")
                return response.read(SIDECARS[pg][1] + 1)
    raw = fetch()
    if (type(raw) is not bytes or len(raw) != SIDECARS[pg][1] or
            hashlib.sha256(raw).hexdigest() != SIDECARS[pg][2] or
            not raw.startswith(b"-----BEGIN PGP SIGNATURE-----")):
        raise ValueError("Detached signature sidecar byte identity changed")
    parsed = subprocess.run(["gpg", "--batch", "--list-packets"], input=raw,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=10, check=False)
    if parsed.returncode != 0:
        raise ValueError("Unparseable OpenPGP signature packet")
    ids = re.findall(rb"keyid ([A-Fa-f0-9]{16})(?![A-Fa-f0-9])", parsed.stdout)
    if len(ids) != 1:
        raise ValueError("Missing or ambiguous OpenPGP signing key hint")
    return ids[0].decode("ascii").upper()


def audit(baseline, release, inspect=None):
    original = strict_baseline(baseline)
    rows = validate_metadata(release, original)
    for row in rows:
        row["untrustedPacketSignerKeyId"] = (inspect or inspect_armored_signature)(row["pgMajor"])
    return {"schemaVersion": "pgextwin-issue112-pgroonga-signature-assets-deny-only/v1",
            "sourceRepo": REPO, "releaseTag": VERSION, "releaseId": RELEASE_ID,
            "reviewedPgMajors": sorted(SIDECARS), "signaturePairs": rows, **DENIED}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", type=Path, default=Path(__file__).resolve().parents[1] /
                   "external/pgroonga-release-watch-baseline-v1.json")
    args = p.parse_args()
    print(json.dumps(audit(args.baseline, github_release()), sort_keys=True))
    print("PGROONGA_SIGNATURE_SIDECARS=ORIGINAL_BYTES_OBSERVED "
          "SIGNER_TRUST=UNVERIFIED PRODUCER_ATTESTATION=UNVERIFIED "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
