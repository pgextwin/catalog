#!/usr/bin/env python3
"""Issue #75 Phase D: independent, authenticated, read-only GitHub snapshots.

NOT a Release verifier, signed-asset validator, publication trigger or PR
proposer. All uncertain, forbidden, paginated or partial responses DENY.
No new schedule, app, secret, write token, or production endpoint is enabled.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from catalog_release_drift import classify
from verified_release_record import ALLOWED, Denied, require

SHA = re.compile(r"^[0-9a-f]{40}$")


def blob_sha(raw):
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()


def unique_json_pairs(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate authenticated Catalog JSON key")
        obj[key] = value
    return obj


class GitHubReadOnly:
    """Explicit GitHub GET-only client; denies incomplete paginated history."""

    def __init__(self, token):
        require(type(token) is str and bool(token), "authenticated read token missing")
        self.token = token

    def get(self, repo, path):
        require(repo == "pgextwin/catalog" or repo in
                {"pgextwin/" + name for name in ALLOWED}, "repository not allowlisted")
        require(type(path) is str and path and
                not any(part in ("..", ".") for part in path.split("/")),
                "unsafe GitHub REST path")
        url = "https://api.github.com/repos/" + repo + "/" + path
        request = Request(url, method="GET", headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        try:
            with urlopen(request, timeout=20) as response:
                require(response.status == 200, "unexpected GitHub HTTP status")
                # Do not infer absence of other public Releases/open PRs from
                # page 1 when an API collection is actually paginated.
                link = response.headers.get("Link", "")
                require(re.search(r'\brel\s*=\s*"?next"?', link, re.I) is None,
                        "incomplete GitHub pagination")
                return json.load(response)
        except HTTPError as exc:
            raise Denied("GitHub read refused (HTTP " + str(exc.code) + ")") from exc
        except (URLError, ValueError) as exc:
            raise Denied("GitHub read unavailable or malformed") from exc


def inspect(api, extension):
    """Inspect live independent main/record/Releases/open-PR snapshots, never write."""
    require(type(extension) is str and extension in ALLOWED,
            "unknown extension in 14-name allowlist")
    extension_repo = "pgextwin/" + extension
    catalog_repo = "pgextwin/catalog"
    main = api.get(catalog_repo, "branches/main")
    main_sha = (main.get("commit") or {}).get("sha") if type(main) is dict else None
    require(type(main_sha) is str and SHA.fullmatch(main_sha),
            "Catalog main SHA not independently resolved")
    record_path = "extensions/" + extension + ".json"
    content = api.get(catalog_repo, "contents/" + record_path + "?ref=" + main_sha)
    require(type(content) is dict and content.get("encoding") == "base64"
            and type(content.get("content")) is str and type(content.get("sha")) is str,
            "Catalog record at resolved main is unavailable")
    try:
        raw = base64.b64decode("".join(content["content"].split()), validate=True)
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_json_pairs)
    except (UnicodeError, binascii.Error, ValueError, TypeError) as exc:
        raise Denied("Catalog record bytes invalid") from exc
    require(content["sha"] == blob_sha(raw),
            "Catalog record API blob SHA mismatch")
    releases = api.get(extension_repo, "releases?per_page=100&page=1")
    require(type(releases) is list and 0 < len(releases) < 100,
            "Release history absent or pagination not independently complete")
    proposals = api.get(catalog_repo, "pulls?state=open&base=main&per_page=100")
    require(type(proposals) is list and len(proposals) < 100,
            "open Catalog PR inventory incomplete")
    blocking = []
    seen_numbers = set()
    for pr in proposals:
        require(type(pr) is dict and type(pr.get("number")) is int
                and pr["number"] > 0 and pr["number"] not in seen_numbers
                and pr.get("state") == "open"
                and (pr.get("base") or {}).get("ref") == "main",
                "untrusted open Catalog PR inventory")
        number = pr["number"]
        seen_numbers.add(number)
        files = api.get(catalog_repo, "pulls/" + str(number) + "/files?per_page=100")
        require(type(files) is list and len(files) < 100,
                "Catalog proposal PR file history incomplete")
        if any(type(item) is not dict for item in files):
            raise Denied("malformed Catalog PR changed file")
        if any(item.get("filename") == record_path or
               item.get("previous_filename") == record_path for item in files):
            blocking.append(number)
    outcome = classify(record, releases)
    if blocking:
        outcome["status"] = "BLOCKED_OPEN_RECORD_PR"
    outcome.update({
        "catalogMainSha": main_sha,
        "catalogRecordBlobSha": content["sha"],
        "publicReleaseCount": len(releases),
        "openRecordProposalPrs": sorted(blocking),
        "gitHubCollectionsComplete": True,
        "candidateArtifactsAndAttestation": "NOT_VERIFIED",
        "source": "authenticated-github-readonly",
        "verifiedSignedRelease": False,
        "proposalAuthorized": False,
        "mutationsEnabled": False,
    })
    return outcome


def main():
    parser = argparse.ArgumentParser(description="Issue 75 read-only Phase D GitHub source probe")
    parser.add_argument("--extension", choices=sorted(ALLOWED), required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(GitHubReadOnly(os.environ.get("GITHUB_TOKEN", "")),
                                 args.extension), sort_keys=True))
        return 0
    except (Denied, ValueError, TypeError, KeyError, OSError) as exc:
        print("PHASE D READ-ONLY DENIED: " + str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
