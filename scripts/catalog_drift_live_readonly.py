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
from urllib.request import Request, build_opener, HTTPRedirectHandler

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class DenyRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None

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
        # Refuse to forward bearer tokens via HTTP redirects.
        self._open = build_opener(DenyRedirect()).open

    @staticmethod
    def allowlisted(repo, path):
        require(type(path) is str and path and len(path) <= 210,
                "invalid GitHub read-only REST path")
        if repo == "pgextwin/catalog":
            if path == "branches/main" or (
                re.fullmatch(r"contents/(?:identities|packages)/([a-z][a-z0-9_]*)\.json\?ref=[0-9a-f]{40}", path)
                and path.split("/")[2].split(".json")[0] in ALLOWED
            ):
                return
            if path == "pulls?state=open&base=main&per_page=100" or (
                re.fullmatch(r"pulls/[1-9][0-9]*/files\?per_page=100", path)
            ):
                return
        if repo in {"pgextwin/" + name for name in ALLOWED}:
            if path == "releases?per_page=100&page=1":
                return
        raise Denied("GitHub GET path not on Catalog read-only allowlist")

    def get(self, repo, path):
        self.allowlisted(repo, path)
        url = "https://api.github.com/repos/" + repo + "/" + path
        request = Request(url, method="GET", headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        try:
            with self._open(request, timeout=20) as response:
                require(response.status == 200, "unexpected GitHub HTTP status")
                # Page-one inventory is never accepted if any next page exists.
                link = response.headers.get("Link", "")
                require(type(link) is str and re.search(
                    r'\brel\s*=\s*"?next"?', link, re.I
                ) is None, "incomplete GitHub pagination")
                body = response.read(MAX_RESPONSE_BYTES + 1)
                require(len(body) <= MAX_RESPONSE_BYTES, "GitHub response too large")
        except HTTPError:
            raise Denied("GitHub read refused or redirected") from None
        except (URLError, ValueError, TypeError, OSError, TimeoutError):
            raise Denied("GitHub read unavailable or malformed") from None
        try:
            return json.loads(body.decode("utf-8"), object_pairs_hook=unique_json_pairs)
        except (UnicodeError, ValueError, TypeError):
            raise Denied("GitHub JSON malformed or duplicated") from None


def _fetch_verified_json_blob(api, catalog_repo, record_path, main_sha, label):
    content = api.get(catalog_repo, "contents/" + record_path + "?ref=" + main_sha)
    require(
        type(content) is dict
        and content.get("encoding") == "base64"
        and type(content.get("content")) is str
        and type(content.get("sha")) is str
        and SHA.fullmatch(content["sha"]) is not None,
        f"Catalog {label} at resolved main is unavailable",
    )
    try:
        raw = base64.b64decode("".join(content["content"].split()), validate=True)
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_json_pairs)
    except (UnicodeError, binascii.Error, ValueError, TypeError) as exc:
        raise Denied(f"Catalog {label} bytes invalid") from exc
    require(content["sha"] == blob_sha(raw), f"Catalog {label} API blob SHA mismatch")
    return parsed, content["sha"]


def inspect(api, extension):
    """Inspect live independent main/identity/ledger/Releases/open-PR snapshots, never write."""
    require(type(extension) is str and extension in ALLOWED,
            "unknown extension in 14-name allowlist")
    extension_repo = "pgextwin/" + extension
    catalog_repo = "pgextwin/catalog"
    main = api.get(catalog_repo, "branches/main")
    main_sha = (main.get("commit") or {}).get("sha") if type(main) is dict else None
    require(type(main_sha) is str and SHA.fullmatch(main_sha),
            "Catalog main SHA not independently resolved")
    identity_path = "identities/" + extension + ".json"
    identity, identity_sha = _fetch_verified_json_blob(
        api, catalog_repo, identity_path, main_sha, "identity"
    )
    require(
        type(identity) is dict
        and identity.get("schemaVersion") == 1
        and identity.get("name") == extension,
        "Catalog identity at resolved main is malformed",
    )
    intake = identity.get("intake")
    dist = identity.get("distribution")
    expected_ledger_path = "packages/" + extension + ".json"
    require(
        type(intake) is dict
        and intake.get("class") == "distributed"
        and intake.get("distributionAllowed") is True
        and intake.get("expectedUpstreamRepository") == ALLOWED[extension]
        and identity.get("upstreamRepository") == ALLOWED[extension]
        and type(dist) is dict
        and dist.get("repository") == extension_repo
        and dist.get("ledgerPath") == expected_ledger_path,
        "Catalog identity is not an authorized distributed repository",
    )
    ledger_path = dist["ledgerPath"]
    ledger, ledger_sha = _fetch_verified_json_blob(
        api, catalog_repo, ledger_path, main_sha, "record"
    )
    releases = api.get(extension_repo, "releases?per_page=100&page=1")
    require(type(releases) is list and 0 < len(releases) < 100,
            "Release history absent or pagination not independently complete")
    proposals = api.get(catalog_repo, "pulls?state=open&base=main&per_page=100")
    require(type(proposals) is list and len(proposals) < 100,
            "open Catalog PR inventory incomplete")
    blocking = []
    seen_numbers = set()
    watched_paths = {identity_path, ledger_path}
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
        if any(item.get("filename") in watched_paths or
               item.get("previous_filename") in watched_paths for item in files):
            blocking.append(number)
    outcome = classify(ledger, releases, identity=identity)
    if blocking:
        outcome["status"] = "BLOCKED_OPEN_RECORD_PR"
    outcome.update({
        "catalogMainSha": main_sha,
        "catalogIdentityBlobSha": identity_sha,
        "catalogRecordBlobSha": ledger_sha,
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
