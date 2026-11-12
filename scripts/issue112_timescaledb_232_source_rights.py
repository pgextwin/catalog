#!/usr/bin/env python3
"""Exact 2.32.0 tagged source-rights continuity, NEVER binary/public admission.

Reuse the existing 2.31.0 fail-closed rights gate and the independently pinned
2.32.0 original-ZIP ledger. This audit only GETs immutable source text through
GitHub; it never retrieves a ZIP, signs, issues admission or publishes.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request

from issue112_timescaledb_rights_gate import (
    DOCS, strict_json, validate as validate_historical,
)
from issue112_timescaledb_232_evidence import verified_assets

ROOT = Path(__file__).resolve().parents[1]
API = "https://api.github.com/repos/timescale/timescaledb"
TAG = "2.32.0"
COMMIT = "b0474c32504c54edb44a23d33dc8a783745600cd"
WORKFLOW = ".github/workflows/release_release.yml"
WORKFLOW_BLOB = "f9cab87e5116a23f0b116690b8b3598e8c598a71"
PINS = {**DOCS, WORKFLOW: WORKFLOW_BLOB}
LATEST = "external/timescaledb-release-watch-observation-2.32.0.json"
HISTORICAL = "external/timescaledb-release-watch-baseline-v1.json"
HISTORICAL_RIGHTS = "external/timescaledb-rights-provenance-intake-v1.json"
DELEGATED = "timescale/release-build-scripts/.github/workflows/timescaledb-windows.yml@main"
SOURCE_MARKERS = {
    "LICENSE": ("Outside of the \"tsl\" directory", "Within the \"tsl\" folder",
                "separate shared object files"),
    "LICENSE-APACHE": ("Apache License", "Version 2.0"),
    "NOTICE": ("TimescaleDB (TM)", "LICENSE-APACHE", "LICENSE-TIMESCALE"),
    "tsl/LICENSE-TIMESCALE": ("TIMESCALE LICENSE AGREEMENT", "2.1", "2.2"),
    WORKFLOW: (DELEGATED, "upload-artifacts: true", "publish_release"),
}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("Source evidence redirect denied")

def github_json(url):
    if not url.startswith(API + "/") or len(url) > 300:
        raise ValueError("Unapproved source API endpoint")
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "pgextwin-timescaledb-232-rights-deny-only",
               "X-GitHub-Api-Version": "2022-11-28"}
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(urllib.request.Request(url, headers=headers), timeout=15) as response:
        if response.status != 200:
            raise ValueError("Unexpected authenticated-source response")
        payload = response.read(256_001)
    if len(payload) > 256_000:
        raise ValueError("Oversized source API receipt")
    def no_duplicates(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("Duplicate GitHub JSON field")
            out[key] = value
        return out
    return json.loads(payload.decode("utf-8"), object_pairs_hook=no_duplicates)

def blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") +
                        b"\x00" + data).hexdigest()

def tagged_sources(get_json, expected):
    ref = get_json(API + "/git/ref/tags/" + TAG)
    if (type(ref) is not dict or ref.get("ref") != "refs/tags/" + TAG or
        ref.get("object") != {
            "sha": COMMIT, "type": "commit",
            "url": API + "/git/commits/" + COMMIT
        }):
        raise ValueError("Unreviewed TimescaleDB source tag/ref")
    texts = {}
    for path, expected_sha in expected.items():
        row = get_json(API + "/contents/" + path + "?ref=" + COMMIT)
        if (type(row) is not dict or row.get("path") != path or
            row.get("sha") != expected_sha or
            row.get("encoding") != "base64" or
            type(row.get("content")) is not str):
            raise ValueError("Unreviewed tagged source file: " + path)
        try:
            data = base64.b64decode(row["content"])
            if len(data) > 100_000 or blob_sha(data) != expected_sha:
                raise ValueError("Tagged Git blob bytes changed: " + path)
            text = data.decode("utf-8")
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Invalid tagged source text: " + path) from exc
        if any(marker not in text for marker in SOURCE_MARKERS[path]):
            raise ValueError("Pinned source rights/build statement missing: " + path)
        texts[path] = text
    if set(texts) != set(PINS):
        raise ValueError("Incomplete 2.32.0 tagged license/NOTICE receipts")
    return True

def audit(root=ROOT, get_json=github_json, test_pins=None):
    # Substitutable source bytes are strictly an offline test fixture. The
    # production CLI always uses exact independently authenticated blob pins.
    expected = PINS if test_pins is None else test_pins
    if (type(expected) is not dict or set(expected) != set(PINS) or
        any(type(value) is not str or re.fullmatch(r"[a-f0-9]{40}", value) is None
            for value in expected.values())):
        raise ValueError("Malformed tagged source inventory")
    historical = strict_json(Path(root) / HISTORICAL)
    historical_rights = strict_json(Path(root) / HISTORICAL_RIGHTS)
    validate_historical(historical_rights, historical)
    latest = strict_json(Path(root) / LATEST)
    if (latest.get("sourceRepo") != "timescale/timescaledb" or
        latest.get("releaseTag") != TAG or latest.get("releaseId") != 442824242 or
        any(latest.get(k) is not False for k in (
            "downloadAuthorized", "publicationAuthorized",
            "redistributionAuthorized"))):
        raise ValueError("New release baseline or DENY state changed")
    originals = verified_assets(root, latest)
    if set(originals) != {"16", "17", "18"}:
        raise ValueError("Missing latest original ZIP evidence")
    tagged_sources(get_json, expected)
    return {
        "schemaVersion": "pgextwin-issue112-timescaledb-232-tagged-source-rights/v1",
        "scope": "SOURCE_DOCUMENT_CONTINUITY_ONLY_CANDIDATE_NONPUBLISHING",
        "repository": "timescale/timescaledb",
        "tag": TAG, "tagCommit": COMMIT,
        "sourceBlobs": dict(sorted(PINS.items())),
        "rightsDocumentsSameBlobsAs231": all(
            PINS[name] == historical_rights["upstream"]["documents"][name]
            for name in DOCS),
        "originalZipMajorsIndependentlyPinned": sorted(originals),
        "delegatedWindowsWorkflow": DELEGATED,
        "delegatedWorkflowCommitPinned": False,
        "delegatedProducerRunToOriginalZipSignedProvenanceVerified": False,
        "perBinaryLicenseNoticeClosureVerified": False,
        "runtimeAndBundledDependenciesClosed": False,
        "sourceSpecificOwnerSignedAdmissionVerified": False,
        "publicGetAuthorized": False,
        "mirrorAuthorized": False,
        "redistributionAuthorized": False,
        "releaseAuthorized": False,
        "publisherAuthorized": False,
    }

def main():
    print(json.dumps(audit(), sort_keys=True, ensure_ascii=True))
    print("TIMESCALEDB_232_SOURCE_RIGHTS=CONTINUITY_ONLY "
          "BINARY_RIGHTS=UNVERIFIED PRODUCER_SIGNATURE=UNVERIFIED "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")

if __name__ == "__main__":
    main()
