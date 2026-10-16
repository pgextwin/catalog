#!/usr/bin/env python3
"""Issue #112: single-identity historical pg_bigm PG14 formal P1 bridge.

Nonpublishing and entirely offline. The Release-wide original-byte gate MUST
finish before the historical row's real gh/TUF/SLSA/SPDX verifier is called.
Never use this bridge for normal Promotion, other PG majors or other extensions.
No fixture, ledger assertion, receipt or archive hash alone can grant admission.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
from decimal import Decimal, InvalidOperation
import shutil
from pathlib import Path
import sys
import tarfile
import tempfile

from distribution_manifest_v1 import Denied, require, safe_path, safe_component, strict_json
from distribution_historical_p1_pg14 import (
    PIN, audit as real_pg14_audit, parse_original_historical_sums,
    validate_fixed_catalog, validate_original_metadata,
)
from distribution_historical_p1_intake_ledger import (
    RECEIPT_SHA, RECEIPT_FIELDS,
)

ARCHIVE_NAME = "pgextwin-issue112-pgbigm-release16-resume6-20261016-evidence.tar.gz"
ARCHIVE_SHA = "bc4f0ce2c43f246e2535510eb0bad34e380db15f6b57c97a831b3c42b8d37744"
ARCHIVE_SIZE = 1860126
MANIFEST_SHA = "8ef9b921fd20098b02bd810fef4c6d1b70e0562c8158ec8d876d4298ce0ff98b"
LEDGER_SHA = "5cdf97e5e36e1a224802a73ba108446dfc95ec399f46faee303d5fd4a35d1b29"
SEAL_SHA = "6dd3e6cb96dbc815bc5df9eb926a9ea29be649ddb2eec825987279f62e2124f7"
PG14_ARCHIVE_SHA = "4e126798ea4fa84b50c441143ff3294d675831843c3b2bb3e57ff8a2f30e9ba3"
PG14_ARCHIVE_SIZE = 533654
PRIOR_ARCHIVE_NAME = "pgextwin-issue112-pgbigm-release16-audit-20261016-evidence.tar.gz"
PRIOR_ARCHIVE_SHA = "738ca743532922330c7bfad620d90d2e893a75aad02650f9d3dbe8b8407da491"
PRIOR_ARCHIVE_SIZE = 1740900
OFFICIAL_GH_SHA = "7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b"
MAX_TAR_BYTES = 4 * 1024 * 1024
MAX_MEMBER = 4 * 1024 * 1024
MAX_TOTAL = 24 * 1024 * 1024
MAX_ENTRIES = 500
HEX = set("0123456789abcdef")


def same(actual, expected, label):
    require(type(actual) is type(expected) and actual == expected, label + " mismatch")


def pinned_bytes(path, size, digest):
    require(isinstance(path, Path) and path.is_file() and not path.is_symlink(),
            "missing, symlink or nonfile original")
    require(path.stat().st_size == size, "external evidence size mismatch")
    data = path.read_bytes()
    same(hashlib.sha256(data).hexdigest(), digest, "external SHA256")
    return data


def sealed_json(path, digest, limit):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
            "missing/linked/oversized JSON")
    data = path.read_bytes()
    same(hashlib.sha256(data).hexdigest(), digest, "external JSON SHA256")
    return data, strict_json(data)


PG14_CACHE_PREFIX = "release-408449466-reaudit/cli-cache/gh/.sigstore/"
PG14_PREFIX = "release-408449466-reaudit/"
SELF_MANIFEST = "EVIDENCE-MANIFEST.json"
PRIOR_MANIFEST_SHA = "c4bf357c26836cf27587c45a8c18298955666af53d8e703d058437df13769cc6"


def historical_tar_path(name, *, allow_pg14_cache=False):
    """Tar-only cache exception; NEVER relax general ZIP or Catalog path rules."""
    if allow_pg14_cache and name.startswith(PG14_CACHE_PREFIX):
        remain = name[len(PG14_CACHE_PREFIX):]
        require(remain and not any(x in (".", "..", "") for x in remain.split("/")),
                "unsafe historical Sigstore cache path")
        for component in remain.split("/"):
            safe_component(component)
        return name
    return safe_path(name)


def safe_tar(blob, *, expected_count=None, allow_pg14_cache=False):
    """Read only bounded original files; PAX permits numeric mtime and exact long path."""
    require(type(blob) is bytes and 0 < len(blob) <= MAX_TAR_BYTES, "tar too large")
    entries, total, folded = {}, 0, set()
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            count = 0
            for member in tf:
                count += 1
                require(count <= MAX_ENTRIES, "too many tar members")
                require((member.isfile() or member.isdir()) and not member.issym()
                        and not member.islnk() and not getattr(member, "sparse", None),
                        "link/special tar member forbidden")
                name = member.name.rstrip("/") if member.isdir() else member.name
                historical_tar_path(name, allow_pg14_cache=allow_pg14_cache)
                pax = member.pax_headers
                require(type(pax) is dict and set(pax) <= {"mtime", "path"},
                        "unknown/dangerous PAX header")
                if "mtime" in pax:
                    raw = pax["mtime"]
                    require(type(raw) is str and re.fullmatch(r"[0-9]{9,12}\.[0-9]{1,9}", raw),
                            "invalid PAX mtime")
                    try:
                        require(0 < Decimal(raw) < Decimal("4102444800"), "PAX mtime out of bounds")
                    except InvalidOperation as exc:
                        raise Denied("invalid PAX mtime") from exc
                if "path" in pax:
                    require(type(pax["path"]) is str and pax["path"] == name
                            and len(name.encode("utf-8")) > 100
                            and allow_pg14_cache and name.startswith(PG14_PREFIX),
                            "PAX path override not allowed")
                folded_name = name.casefold()
                require(folded_name not in folded, "duplicate/case-colliding tar entry")
                folded.add(folded_name)
                if member.isdir():
                    require(member.size == 0, "nonempty tar directory")
                    continue
                require(0 <= member.size <= MAX_MEMBER, "oversized tar member")
                total += member.size
                require(total <= MAX_TOTAL, "tar decompression bound")
                f = tf.extractfile(member)
                require(f is not None, "unreadable tar member")
                data = f.read(member.size + 1)
                require(len(data) == member.size, "tar member byte length mismatch")
                entries[name] = data
            require(count > 0, "empty tar")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise Denied("invalid compressed tar") from exc
    if expected_count is not None:
        same(len(entries), expected_count, "archived member count")
    return entries


def check_self_manifest(entries, *, original, original_sha, count):
    """Exactly count data members plus one byte-exact self-manifest; no extras."""
    require(SELF_MANIFEST in entries, "missing inner self-manifest")
    same(hashlib.sha256(entries[SELF_MANIFEST]).hexdigest(), original_sha,
         "self-manifest external SHA256")
    same(entries[SELF_MANIFEST], original, "inner/outer manifest byte identity")
    same(len(entries), count + 1, "manifest+payload total entry count")
    return {k: v for k, v in entries.items() if k != SELF_MANIFEST}


def validate_manifest(entries, manifest):
    require(type(manifest) is dict
            and manifest.get("schema") == "pgextwin-issue112-resume6-manifest/v1"
            and manifest.get("repoId") == PIN["repoId"]
            and manifest.get("releaseId") == PIN["releaseId"]
            and manifest.get("publicationAuthorized") is False
            and manifest.get("distributionAuthorized") is False
            and manifest.get("signatureOrTrustedTimestamp") is False,
            "untrusted release manifest")
    files = manifest.get("files")
    require(type(files) is list and len(files) == 31, "31-file manifest missing")
    names = set()
    for f in files:
        require(type(f) is dict and set(f) == {"path", "size", "sha256"},
                "malformed file manifest")
        path = safe_path(f["path"])
        require(path not in names and path in entries, "missing/duplicate manifest file")
        names.add(path)
        require(type(f["size"]) is int and f["size"] >= 0
                and type(f["sha256"]) is str and len(f["sha256"]) == 64
                and set(f["sha256"]) <= HEX, "malformed file hash")
        same(len(entries[path]), f["size"], "manifest member size")
        same(hashlib.sha256(entries[path]).hexdigest(), f["sha256"], "manifest member digest")
    same(set(entries), names, "extra archived members")


def validate_nested_prior_manifest(entries, manifest):
    """Independently inspect all 59 files of the previously sealed 10-Asset archive."""
    require(type(manifest) is dict and type(manifest.get("files")) is list
            and len(manifest["files"]) == 59, "old 59-file manifest missing")
    recorded = {}
    for item in manifest["files"]:
        require(type(item) is dict and
                {"path", "size", "sha256"}.issubset(item),
                "old manifest member malformed")
        name = safe_path(item["path"])
        require(name not in recorded and type(item["size"]) is int
                and type(item["sha256"]) is str
                and len(item["sha256"]) == 64 and set(item["sha256"]) <= HEX,
                "old manifest duplicate or invalid entry")
        recorded[name] = item
    same(set(entries), set(recorded), "old 59 archived members")
    for name, item in recorded.items():
        same(len(entries[name]), item["size"], "old manifest entry size")
        same(hashlib.sha256(entries[name]).hexdigest(), item["sha256"],
             "old manifest entry SHA256")


def validate_pg14_manifest(pg14_outer):
    """PG14-specific embedded 69+1 archive layout, not general tar allowance."""
    pg14_manifest_key = PG14_PREFIX + SELF_MANIFEST
    require(pg14_manifest_key in pg14_outer, "missing PG14 self-manifest")
    pg14_manifest = strict_json(pg14_outer[pg14_manifest_key])
    require(type(pg14_manifest) is dict
            and pg14_manifest.get("schema") == "pgextwin-issue112-reaudit-sha256-manifest/v1"
            and pg14_manifest.get("releaseId") == PIN["releaseId"]
            and pg14_manifest.get("catalogSnapshotCommit") == PIN["catalog"]
            and pg14_manifest.get("publicationAuthorized") is False
            and type(pg14_manifest.get("files")) is list
            and len(pg14_manifest["files"]) == 69, "incorrect PG14 self-manifest")
    entries = {name: data for name, data in pg14_outer.items() if name != pg14_manifest_key}
    recorded = {}
    for item in pg14_manifest["files"]:
        require(type(item) is dict and set(item) == {"path", "size", "sha256"},
                "invalid PG14 manifest member")
        rel = item["path"]
        name = PG14_PREFIX + rel
        historical_tar_path(name, allow_pg14_cache=True)
        require(name not in recorded and type(item["size"]) is int
                and item["size"] >= 0 and type(item["sha256"]) is str
                and len(item["sha256"]) == 64 and set(item["sha256"]) <= HEX,
                "invalid PG14 manifest entry")
        recorded[name] = item
    same(set(entries), set(recorded), "PG14 69-file manifest membership")
    for name, item in recorded.items():
        same(len(entries[name]), item["size"], "PG14 original member size")
        same(hashlib.sha256(entries[name]).hexdigest(), item["sha256"],
             "PG14 original member SHA256")
    return entries


def check_seal(seal, ledger_bytes, manifest_bytes):
    require(type(seal) is dict and
            seal.get("schema") == "pgextwin-issue112-resume6-seal/v1",
            "wrong seal")
    for key, name, size, digest in (
        ("archive", ARCHIVE_NAME, ARCHIVE_SIZE, ARCHIVE_SHA),
        ("ledger", "pgextwin-issue112-pgbigm-release16-resume6-20261016-ledger.json",
         len(ledger_bytes), LEDGER_SHA),
        ("manifest", "pgextwin-issue112-pgbigm-release16-resume6-20261016-manifest.json",
         len(manifest_bytes), MANIFEST_SHA),
    ):
        obj = seal.get(key)
        require(type(obj) is dict and obj.get("name") == name
                and obj.get("size") == size and obj.get("sha256") == digest,
                "seal component differs: " + key)
    same(seal["manifest"].get("fileCount"), 31, "sealed file count")
    for key, expected in (("all16AssetsRehashed", True), ("newAssetsVerified", 6),
                          ("reusedAssetsRehashed", 10), ("formalP1Accepted", 0),
                          ("historicalSourceAccepted", 0), ("publicationAuthorized", False),
                          ("distributionAuthorized", False), ("signatureOrTrustedTimestamp", False)):
        same(seal.get(key), expected, "seal status " + key)


def ledger_assets(ledger):
    require(type(ledger) is dict and
            ledger.get("schema") == "pgextwin-issue112-resume6-release-byte-audit/v1",
            "wrong Release ledger schema")
    for key, expected in (
        ("implementationCommit", "6a3a9810e7783e29fc93dd740c25c721374a2d01"),
        ("buildCommit", "0466d7275473cd88a95de650c4ac002c7941a67f"),
        ("catalogSnapshot", PIN["catalog"]), ("repoId", PIN["repoId"]),
        ("releaseId", PIN["releaseId"]), ("all16AssetsRehashed", True),
        ("all15ChecksumPayloadsMatch", True), ("totalAssetPayloadsVerified", 16),
        ("checksumPayloadsVerified", 15), ("newAssetsVerified", 6),
        ("reusedAssetsRehashed", 10), ("formalP1Accepted", 0),
        ("historicalSourceAccepted", 0), ("formalP1RowAccepted", False),
        ("signatureVerificationExecutedThisRun", False),
        ("tufRevalidationExecutedThisRun", False),
        ("sourceRunAttemptVerificationExecutedThisRun", False),
        ("publicationAuthorized", False), ("distributionAuthorized", False),
        ("fleetComplete", False), ("p1", "BLOCKED"), ("p2", "NO-GO"),
        ("formalDistribution", "DENY"),
        ("originalChecksumSha256", PIN["sumsSha256"]),
        ("decision", "PASS_LIMITED_RELEASE_BYTE_AUDIT_ONLY"),
    ):
        same(ledger.get(key), expected, "ledger " + key)
    same(ledger.get("errors"), [], "ledger audit errors")
    assets = ledger.get("assets")
    require(type(assets) is list and len(assets) == 16, "not 16 original Assets")
    by_name = {}
    ids = set()
    for a in assets:
        require(type(a) is dict and type(a.get("id")) is int
                and type(a.get("name")) is str and a["name"] not in by_name
                and a["id"] not in ids, "duplicate/invalid original asset")
        by_name[a["name"]] = a
        ids.add(a["id"])
        for k, expected in (("state", "uploaded"), ("result", "PASS"),
                            ("actualSize", a.get("size")),
                            ("expectedSha256", a.get("digest", "")[7:]),
                            ("actualSha256", a.get("digest", "")[7:])):
            same(a.get(k), expected, "ledger asset " + k)
        if a["name"] != "SHA256SUMS.txt":
            same(a.get("checksumMatches"), True, "asset checksum payload comparison")
        else:
            same(a.get("checksumMatches"), None, "checksum file self-comparison")
        same(a.get("url"),
             "https://api.github.com/repos/" + PIN["repo"] + "/releases/assets/" +
             str(a["id"]), "asset numeric ID URL")
        same(a.get("browser_download_url"),
             "https://github.com/" + PIN["repo"] + "/releases/download/" + PIN["tag"]
             + "/" + a["name"], "asset original URL")
    same(by_name[PIN["asset"]]["id"], PIN["assetId"], "PG14 asset numeric ID")
    same(by_name["SHA256SUMS.txt"]["id"], PIN["sumsAssetId"], "sums numeric ID")
    return by_name


def identify_asset_bytes(new_entries, prior_entries, pg14_entries, by_name):
    """Use only the three immutable, externally pinned archive storage locations."""
    pg14 = {PIN["asset"], "SHA256SUMS.txt",
            "pg_bigm-v1.2-20250903-pg14-windows-x64.spdx.json",
            "pg_bigm-v1.2-20250903-pg14-windows-x64.vulnerabilities.json"}
    newly = {n for n, a in by_name.items() if a.get("origin") == "NEW_GET_THIS_RUN"}
    old = set(by_name) - newly
    require(len(newly) == 6 and len(old) == 10 and pg14 <= old,
            "PG14/15/16 preserved and PG17/18 newly fetched matrix mismatch")
    actual = {}
    for name in by_name:
        if name in pg14:
            path = PG14_PREFIX + "snapshot/assets/" + name
            source = pg14_entries
        elif name in newly:
            require("-pg17-" in name or "-pg18-" in name, "new Asset PG-major mismatch")
            path, source = "resume6/new-assets/" + name, new_entries
        else:
            require("-pg15-" in name or "-pg16-" in name, "preserved PG-major mismatch")
            path, source = "audit/new-assets/" + name, prior_entries
        require(path in source, "missing original Release payload at exact path: " + path)
        blob = source[path]
        same(len(blob), by_name[name]["size"], "original Asset byte size")
        same(hashlib.sha256(blob).hexdigest(), by_name[name]["digest"][7:],
             "original Asset SHA256")
        actual[name] = blob
    same(set(actual), set(by_name), "16 original payloads")
    sums = actual["SHA256SUMS.txt"]
    same(len(sums), 1780, "historical checksum size")
    same(hashlib.sha256(sums).hexdigest(), PIN["sumsSha256"], "historical checksum SHA256")
    for name, digest in parse_original_historical_sums(sums, set(actual) - {"SHA256SUMS.txt"}).items():
        same(digest, hashlib.sha256(actual[name]).hexdigest(),
             "15 checksum rows against real payload")
    return actual


def validate_receipt_pins(receipt):
    require(type(receipt) is dict and set(RECEIPT_FIELDS).issubset(receipt),
            "historical PG14 receipt incomplete")
    for key, value in RECEIPT_FIELDS.items():
        same(receipt.get(key), value, "old PG14 receipt identity " + key)
    bundles = receipt.get("verifiedBundleSha256")
    require(type(bundles) is dict and
            set(bundles) == {"https://slsa.dev/provenance/v1",
                             "https://spdx.dev/Document/v2.3"}
            and all(type(x) is str and len(x) == 64 and set(x) <= HEX
                    for x in bundles.values()),
            "old receipt missing both cryptographically verified predicates")


def find_original_snapshot(entries):
    """Find one unambiguous original verifier input tree; never trust a receipt path."""
    suffixes = {"index.json", "pg_bigm.json", "release.json",
                "windows.yml", "extension.json", "run.json", "jobs.json",
                "pg14-job.log", "upstream-commit.json",
                PIN["asset"] + ".jsonl",
                "assets/" + PIN["asset"], "assets/SHA256SUMS.txt"}
    prefix_candidates = []
    for path in entries:
        if path.endswith("index.json"):
            prefix = path[:-len("index.json")]
            if all(prefix + suffix in entries for suffix in suffixes):
                prefix_candidates.append(prefix)
    require(len(prefix_candidates) == 1, "unique original PG14 verifier snapshot unavailable")
    prefix = prefix_candidates[0]
    require(prefix == PG14_PREFIX + "snapshot/", "PG14 snapshot prefix mismatch")
    return {name[len(prefix):]: blob for name, blob in entries.items()
            if name.startswith(prefix)}


def verify_official_gh():
    """Require the independently Work-pinned genuine gh 2.102.0 executable bytes."""
    executable = shutil.which("gh")
    require(executable is not None, "verified official gh unavailable")
    path = Path(executable)
    require(path.is_file() and not path.is_symlink(), "gh executable link rejected")
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    same(digest.hexdigest(), OFFICIAL_GH_SHA, "independently pinned official gh")


def gate(release_archive, manifest_file, ledger_file, seal_file,
         prior_pg14_archive, receipt_file, trusted_root):
    """The sole admission boundary. NOT callable through P2/Publisher paths."""
    manifest_bytes, manifest = sealed_json(manifest_file, MANIFEST_SHA, 16384)
    ledger_bytes, ledger = sealed_json(ledger_file, LEDGER_SHA, 65536)
    _, seal = sealed_json(seal_file, SEAL_SHA, 4096)
    check_seal(seal, ledger_bytes, manifest_bytes)
    release = pinned_bytes(release_archive, ARCHIVE_SIZE, ARCHIVE_SHA)
    outer_entries = safe_tar(release, expected_count=32)
    entries = check_self_manifest(outer_entries, original=manifest_bytes,
                                  original_sha=MANIFEST_SHA, count=31)
    validate_manifest(entries, manifest)
    same(entries["resume6/ledger.json"], ledger_bytes, "archived ledger byte identity")
    by_name = ledger_assets(ledger)
    original_release = strict_json(entries["resume6/current/release.json"])
    original_repository = strict_json(entries["resume6/current/repository.json"])
    for key, expect in (("id", PIN["releaseId"]), ("tag_name", PIN["tag"]),
                        ("target_commitish", PIN["packaging"]),
                        ("draft", False), ("prerelease", False)):
        same(original_release.get(key), expect, "original Release metadata " + key)
    same(original_repository.get("id"), PIN["repoId"], "original numeric repository ID")
    observed = original_release.get("assets")
    require(type(observed) is list and len(observed) == 16, "original Release 16 assets missing")
    observed_by_name = {x.get("name"): x for x in observed if type(x) is dict}
    same(set(observed_by_name), set(by_name), "original Release names")
    for name, actual in by_name.items():
        for field in ("id", "name", "size", "digest", "state", "browser_download_url"):
            same(actual.get(field), observed_by_name[name].get(field),
                 "original Release Asset numeric identity " + field)
    prior_blob = entries["preserved-previous-run/" + PRIOR_ARCHIVE_NAME]
    same(len(prior_blob), PRIOR_ARCHIVE_SIZE, "nested prior archive size")
    same(hashlib.sha256(prior_blob).hexdigest(), PRIOR_ARCHIVE_SHA,
         "nested prior archive SHA256")
    prior_outer = safe_tar(prior_blob, expected_count=60)
    nested_manifest_name = ("preserved-previous-run/"
                            "pgextwin-issue112-pgbigm-release16-audit-20261016-manifest.json")
    prior_manifest_bytes = entries[nested_manifest_name]
    same(hashlib.sha256(prior_manifest_bytes).hexdigest(), PRIOR_MANIFEST_SHA,
         "externally pinned prior manifest")
    prior_entries = check_self_manifest(prior_outer, original=prior_manifest_bytes,
                                        original_sha=PRIOR_MANIFEST_SHA, count=59)
    validate_nested_prior_manifest(prior_entries, strict_json(prior_manifest_bytes))
    old_blob = pinned_bytes(prior_pg14_archive, PG14_ARCHIVE_SIZE, PG14_ARCHIVE_SHA)
    same(prior_entries["preserved-original/pgextwin-issue112-pgbigm-pg14-reaudit-evidence-20261016.tar.gz"],
         old_blob, "nested PG14 original archive byte identity")
    pg14_outer = safe_tar(old_blob, expected_count=70, allow_pg14_cache=True)
    old_entries = validate_pg14_manifest(pg14_outer)
    # Gate 1: complete original Release payload checks precede all cryptographic checks.
    original = identify_asset_bytes(entries, prior_entries, old_entries, by_name)
    # Gate 2: original historical receipt, root and real gh cryptography.
    snapshot = find_original_snapshot(old_entries)
    receipt_data = pinned_bytes(receipt_file, 1856, RECEIPT_SHA)
    receipt = strict_json(receipt_data)
    validate_receipt_pins(receipt)
    # Signed PG14 original bytes must be the identical bytes authenticated in Gate 1.
    for name in (PIN["asset"], "SHA256SUMS.txt"):
        same(snapshot["assets/" + name], original[name],
             "signed PG14 bytes differ from all-16 Release")
    require(trusted_root.is_file() and not trusted_root.is_symlink()
            and hashlib.sha256(trusted_root.read_bytes()).hexdigest() == PIN["rootSha256"],
            "untrusted original TUF Root")
    # No caller-provided status or mocked receipt is accepted as a verification.
    verify_official_gh()
    with tempfile.TemporaryDirectory(prefix="pgextwin-issue112-bridge-") as folder:
        root = Path(folder)
        for name, blob in snapshot.items():
            safe_path(name)
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
        record, _ = validate_fixed_catalog(root, PIN["catalog"])
        metadata = validate_original_metadata(record, strict_json(snapshot["release.json"]))
        for name, item in by_name.items():
            md = metadata[name]
            for field in ("id", "size", "digest", "name"):
                same(item.get(field), md.get(field), "immutable Release asset " + field)
        verified = real_pg14_audit(root, trusted_root, PIN["catalog"])
    same(verified, receipt, "reexecuted genuine PG14 Sigstore result vs original receipt")
    require(verified.get("signatureVerified") is True
            and verified.get("rowEvidenceComplete") is True
            and verified.get("integrityVerified") is True
            and verified.get("publicationAuthorized") is False,
            "PG14 original real cryptographic verification not complete")
    return {
        "profile": "historical-pg_bigm-pg14-formal-bridge/v1",
        "decision": "PG14_SINGLE_ROW_ADMITTED", "releaseAssetsRehashed": 16,
        "checksumPayloadsCompared": 15, "originalPG14RealSigstoreVerified": True,
        "formalP1RowsAccepted": 1, "formalP1RowsExpected": 70,
        "historicalSourceAccepted": 0, "historicalSourceExpected": 40,
        "p1": "BLOCKED", "p2": "NO-GO", "fleetComplete": False,
        "publicationAuthorized": False, "distributionAuthorized": False,
        "distribution": "DENY",
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--historical-pg-bigm-pg14", action="store_true", required=True)
    p.add_argument("--release-archive", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--ledger", type=Path, required=True)
    p.add_argument("--seal", type=Path, required=True)
    p.add_argument("--prior-pg14-archive", type=Path, required=True)
    p.add_argument("--pg14-receipt", type=Path, required=True)
    p.add_argument("--trusted-root", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        result = gate(args.release_archive, args.manifest, args.ledger, args.seal,
                      args.prior_pg14_archive, args.pg14_receipt, args.trusted_root)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Denied, OSError, TypeError, ValueError, KeyError, AttributeError) as exc:
        print(json.dumps({"decision": "DENY", "formalP1RowsAccepted": 0,
                          "historicalSourceAccepted": 0, "p1": "BLOCKED",
                          "p2": "NO-GO", "publicationAuthorized": False,
                          "distributionAuthorized": False, "reason": str(exc)},
                         sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
