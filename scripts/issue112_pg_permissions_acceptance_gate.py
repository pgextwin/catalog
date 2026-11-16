#!/usr/bin/env python3
"""Fail-closed formal acceptance-gate verifier for pg_permissions 1.4.1 (PG15-18 SQL pilot)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.issue112_pg_permissions_source_pins import NEW_COMMIT, NEW_TAG, PINNED

EXTENSION_NAME = "pg_permissions"
UPSTREAM_REPOSITORY = "cybertec-postgresql/pg_permissions"
PACKAGING_REPOSITORY = "pgextwin/pg_permissions"
PACKAGING_MAIN_COMMIT = "82bcc09c6ba1a33eb1596736b942266613bac8fb"
UPSTREAM_TAG = NEW_TAG
UPSTREAM_COMMIT = NEW_COMMIT
EXTENSION_VERSION = "1.4.1"
SQL_DEFAULT_VERSION = "1.4"
TARGET_ARCH = "windows-x64"
SUPPORTED_PG_MAJORS = (15, 16, 17, 18)
FORBIDDEN_PG_MAJORS = (14,)
ASSET_SUFFIXES = (".zip", ".spdx.json", ".vulnerabilities.json")
SHA256SUMS_NAME = "SHA256SUMS.txt"

CANDIDATE_ARTIFACT_ID = "14027920721"
CANDIDATE_ARTIFACT_EXPIRES_JST = "2026-11-20 19:03:28 JST"

GATE_IDS = (
    "G1_PIN_CHAIN_CENTRAL_REG",
    "G2_PROTECTED_MAIN_AND_OWNER_SIGN",
    "G3_FORMAL_ASSET_SET_13_FILES",
    "G4_SHA256SUMS_AND_ZIP_INTEGRITY",
    "G5_ATTESTED_PACKAGE_INFO_PROVENANCE",
    "G6_SPDX_2_3_AND_GRYPE_CLEAN",
    "G7_SCOPED_PUBLISHER_ADMISSION",
)

BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM"})
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_BASENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_SUMS_BYTES = 256 * 1024


class AcceptanceGateError(ValueError):
    """Raised when formal acceptance-gate inputs violate fail-closed invariants."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise AcceptanceGateError(f"Duplicate JSON key rejected: {k!r}")
        out[k] = v
    return out


def load_strict_json(raw: bytes, label: str) -> dict[str, Any]:
    """Decode a UTF-8 JSON object while rejecting duplicate keys or huge payloads."""
    if len(raw) > MAX_JSON_BYTES:
        raise AcceptanceGateError(f"{label} exceeds {MAX_JSON_BYTES} bytes")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcceptanceGateError(f"Invalid JSON in {label}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AcceptanceGateError(f"{label} must be a JSON object")
    return parsed


def expected_major_assets(major: int) -> tuple[str, str, str]:
    """Return the exact 3 acceptance asset filenames for one supported PG major."""
    if major not in SUPPORTED_PG_MAJORS:
        raise AcceptanceGateError(f"Unsupported PostgreSQL major for pilot: {major!r}")
    stem = f"{EXTENSION_NAME}-{UPSTREAM_TAG}-pg{major}-{TARGET_ARCH}"
    return (f"{stem}.zip", f"{stem}.spdx.json", f"{stem}.vulnerabilities.json")


def expected_formal_assets() -> tuple[str, ...]:
    """Return the exact 13 formal acceptance filenames (12 per-major + SHA256SUMS.txt)."""
    items: list[str] = []
    for major in SUPPORTED_PG_MAJORS:
        items.extend(expected_major_assets(major))
    items.append(SHA256SUMS_NAME)
    return tuple(items)


def sha256_file(path: Path) -> str:
    """Compute lowercase SHA-256 hex digest of a non-symlink regular file."""
    if path.is_symlink() or not path.is_file():
        raise AcceptanceGateError(f"Expected regular non-symlink file: {path}")
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def parse_sha256sums(text: str) -> dict[str, str]:
    """Parse SHA256SUMS.txt strictly, rejecting duplicates, traversal, and malformed rows."""
    parsed: dict[str, str] = {}
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+[*]?(\S+)", line)
        if not match:
            raise AcceptanceGateError(f"Malformed SHA256SUMS.txt line {lineno}: {raw_line!r}")
        digest = match.group(1).lower()
        name = match.group(2)
        if not SAFE_BASENAME_RE.fullmatch(name) or name in {".", ".."}:
            raise AcceptanceGateError(f"Unsafe filename in SHA256SUMS.txt line {lineno}: {name!r}")
        if name in parsed:
            raise AcceptanceGateError(f"Duplicate filename in SHA256SUMS.txt: {name!r}")
        parsed[name] = digest
    return parsed


def _check_safe_zip_member(info: zipfile.ZipInfo) -> None:
    """Reject symlinks and path-traversal entries inside a release ZIP."""
    name = info.filename
    if not name or name.startswith("/") or "\\" in name or ".." in Path(name).parts:
        raise AcceptanceGateError(f"Unsafe ZIP member path: {name!r}")
    unix_mode = (info.external_attr >> 16) & 0o170000
    if unix_mode == stat.S_IFLNK:
        raise AcceptanceGateError(f"Symlink ZIP member rejected: {name!r}")


def _verify_package_info(raw: bytes, major: int, zip_name: str) -> dict[str, Any]:
    info = load_strict_json(raw, f"{zip_name}:PACKAGE-INFO.json")
    schema_version = info.get("schemaVersion")
    if type(schema_version) is not int or schema_version != 1:
        raise AcceptanceGateError(f"{zip_name}: schemaVersion must be 1, got {schema_version!r}")
    if info.get("buildMode") != "release-attested":
        raise AcceptanceGateError(f"{zip_name}: buildMode must be 'release-attested'")
    pkg = info.get("package")
    if not isinstance(pkg, dict) or pkg.get("name") != EXTENSION_NAME:
        raise AcceptanceGateError(f"{zip_name}: invalid package metadata {pkg!r}")
    upstream = info.get("upstream")
    if not isinstance(upstream, dict):
        raise AcceptanceGateError(f"{zip_name}: missing upstream metadata")
    if (
        upstream.get("repository") != UPSTREAM_REPOSITORY
        or upstream.get("ref") != UPSTREAM_TAG
        or upstream.get("version") != EXTENSION_VERSION
        or upstream.get("commit") != UPSTREAM_COMMIT
    ):
        raise AcceptanceGateError(f"{zip_name}: upstream identity mismatch: {upstream!r}")
    source = info.get("source")
    packaging_commit = source.get("packagingCommit") if isinstance(source, dict) else None
    if not isinstance(packaging_commit, str) or not HEX40_RE.fullmatch(packaging_commit):
        raise AcceptanceGateError(f"{zip_name}: invalid source.packagingCommit: {source!r}")
    pg = info.get("postgresql")
    if not isinstance(pg, dict) or type(pg.get("major")) is not int or pg.get("major") != major:
        raise AcceptanceGateError(f"{zip_name}: expected postgresql.major={major}, got {pg!r}")
    run = info.get("workflowRun")
    if not isinstance(run, dict):
        raise AcceptanceGateError(f"{zip_name}: missing workflowRun provenance")
    run_id = run.get("id")
    run_attempt = run.get("attempt")
    if (
        type(run_id) is not int
        or run_id <= 0
        or type(run_attempt) is not int
        or run_attempt != 1
        or run.get("event") != "issue_comment"
        or run.get("ref") != "refs/heads/main"
    ):
        raise AcceptanceGateError(f"{zip_name}: workflowRun provenance failed closed: {run!r}")
    return info


def _verify_zip_asset(zip_path: Path, major: int) -> dict[str, Any]:
    if not zipfile.is_zipfile(zip_path):
        raise AcceptanceGateError(f"Not a valid ZIP archive: {zip_path.name}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        bad = zf.testzip()
        if bad is not None:
            raise AcceptanceGateError(f"Corrupted ZIP member {bad!r} in {zip_path.name}")
        pkg_info_raw: bytes | None = None
        for member in zf.infolist():
            _check_safe_zip_member(member)
            if member.filename == "PACKAGE-INFO.json" or member.filename.endswith("/PACKAGE-INFO.json"):
                if pkg_info_raw is not None:
                    raise AcceptanceGateError(f"Multiple PACKAGE-INFO.json entries in {zip_path.name}")
                pkg_info_raw = zf.read(member.filename)
        if pkg_info_raw is None:
            raise AcceptanceGateError(f"Missing PACKAGE-INFO.json in {zip_path.name}")
    return _verify_package_info(pkg_info_raw, major, zip_path.name)


def _verify_spdx_asset(spdx_path: Path) -> dict[str, Any]:
    doc = load_strict_json(spdx_path.read_bytes(), spdx_path.name)
    if doc.get("spdxVersion") != "SPDX-2.3":
        raise AcceptanceGateError(f"{spdx_path.name}: expected spdxVersion 'SPDX-2.3'")
    if doc.get("dataLicense") != "CC0-1.0":
        raise AcceptanceGateError(f"{spdx_path.name}: expected dataLicense 'CC0-1.0'")
    packages = doc.get("packages")
    if not isinstance(packages, list) or len(packages) != 1 or not isinstance(packages[0], dict):
        raise AcceptanceGateError(f"{spdx_path.name}: packages must contain exactly one package object")
    pkg = packages[0]
    files = doc.get("files")
    if pkg.get("filesAnalyzed") is False and "files" not in doc:
        file_count = 0
    elif isinstance(files, list) and files:
        file_count = len(files)
    else:
        raise AcceptanceGateError(
            f"{spdx_path.name}: files must be non-empty list unless single package has filesAnalyzed=false"
        )
    return {"spdxVersion": doc["spdxVersion"], "packageCount": len(packages), "fileCount": file_count}


def _verify_grype_asset(grype_path: Path) -> dict[str, Any]:
    report = load_strict_json(grype_path.read_bytes(), grype_path.name)
    matches = report.get("matches")
    if not isinstance(matches, list):
        raise AcceptanceGateError(f"{grype_path.name}: 'matches' must be a list")
    blocking: list[str] = []
    for item in matches:
        vuln = item.get("vulnerability") if isinstance(item, dict) else None
        sev = str((vuln or {}).get("severity", "")).upper()
        vid = str((vuln or {}).get("id", "unknown"))
        if sev in BLOCKING_SEVERITIES:
            blocking.append(f"{vid}:{sev}")
    if blocking:
        raise AcceptanceGateError(f"{grype_path.name}: blocking vulnerabilities present: {blocking}")
    return {"matchCount": len(matches), "blockingCount": 0}


def verify_formal_asset_dir(asset_dir: Path) -> dict[str, Any]:
    """Fail-closed verification of the 13-file PG15-18 formal acceptance asset set."""
    if not asset_dir.exists() or asset_dir.is_symlink() or not asset_dir.is_dir():
        raise AcceptanceGateError(f"Asset directory must be an existing non-symlink directory: {asset_dir}")

    entries = list(asset_dir.iterdir())
    names: set[str] = set()
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            raise AcceptanceGateError(f"Only regular non-symlink files allowed in {asset_dir}: {entry.name!r}")
        names.add(entry.name)

    expected = set(expected_formal_assets())
    expected_hashed = expected - {SHA256SUMS_NAME}
    has_sums_file = SHA256SUMS_NAME in names
    expected_present = expected if has_sums_file else expected_hashed
    missing = sorted(expected_present - names)
    extra = sorted(names - expected_present)
    if missing or extra:
        raise AcceptanceGateError(f"Formal asset set mismatch: missing={missing}, extra={extra}")

    if has_sums_file:
        sums_path = asset_dir / SHA256SUMS_NAME
        if sums_path.stat().st_size > MAX_SUMS_BYTES:
            raise AcceptanceGateError(f"{SHA256SUMS_NAME} exceeds {MAX_SUMS_BYTES} bytes")
        sums = parse_sha256sums(sums_path.read_text(encoding="utf-8"))
        if set(sums.keys()) != expected_hashed:
            raise AcceptanceGateError(
                f"SHA256SUMS.txt asset set mismatch: missing={sorted(expected_hashed - set(sums))}, "
                f"extra={sorted(set(sums) - expected_hashed)}"
            )
    else:
        sums = {fname: sha256_file(asset_dir / fname) for fname in sorted(expected_hashed)}

    per_major: dict[int, Any] = {}
    for major in SUPPORTED_PG_MAJORS:
        zip_name, spdx_name, grype_name = expected_major_assets(major)
        for fname in (zip_name, spdx_name, grype_name):
            actual = sha256_file(asset_dir / fname)
            if actual != sums[fname]:
                raise AcceptanceGateError(f"SHA-256 mismatch for {fname}: expected {sums[fname]}, got {actual}")
        pkg_info = _verify_zip_asset(asset_dir / zip_name, major)
        spdx_info = _verify_spdx_asset(asset_dir / spdx_name)
        grype_info = _verify_grype_asset(asset_dir / grype_name)
        per_major[major] = {
            "zip": zip_name,
            "sha256": sums[zip_name],
            "buildMode": pkg_info["buildMode"],
            "spdx": spdx_info,
            "grype": grype_info,
        }

    return {
        "extension": EXTENSION_NAME,
        "version": EXTENSION_VERSION,
        "upstreamCommit": UPSTREAM_COMMIT,
        "assetCount": len(expected),
        "majors": per_major,
    }


def evaluate_pilot_status(
    gate_evidence: dict[str, bool] | None = None,
    asset_dir: Path | None = None,
) -> dict[str, Any]:
    """Diagnostic-only status until independently verified formal evidence exists."""
    flags = {gate: False for gate in GATE_IDS}
    # A caller-controlled dict cannot authenticate G1-G7. The eventual
    # publisher admission is evaluated within its separately authorized job.
    if gate_evidence is not None:
        raise AcceptanceGateError("Unverified gate evidence is not formal acceptance proof")

    asset_report: dict[str, Any] | None = None
    if asset_dir is not None:
        asset_report = verify_formal_asset_dir(asset_dir)
        # Internal hashes, PACKAGE-INFO, SPDX and Grype JSON are structural
        # diagnostics, not independent provenance or publication authorization.

    passed = sum(1 for v in flags.values() if v)
    formal_passed = False  # No trusted VerifiedEvidence/PublisherAdmission path yet
    return {
        "extension": EXTENSION_NAME,
        "version": EXTENSION_VERSION,
        "sqlDefaultVersion": SQL_DEFAULT_VERSION,
        "upstream": {
            "repository": UPSTREAM_REPOSITORY,
            "ref": UPSTREAM_TAG,
            "commit": UPSTREAM_COMMIT,
            "pinnedFileCount": len(PINNED),
        },
        "packaging": {
            "repository": PACKAGING_REPOSITORY,
            "mainCommitObserved": PACKAGING_MAIN_COMMIT,
            "supportedMajors": list(SUPPORTED_PG_MAJORS),
            "forbiddenMajors": list(FORBIDDEN_PG_MAJORS),
        },
        "candidateArtifact": {
            "id": CANDIDATE_ARTIFACT_ID,
            "expiresJst": CANDIDATE_ARTIFACT_EXPIRES_JST,
            "formalAccepted": False,
        },
        "gates": flags,
        "passedGates": passed,
        "totalGates": len(GATE_IDS),
        "formalAcceptancePassed": formal_passed,
        "status": "FORMALLY_ACCEPTED" if formal_passed else "CANDIDATE_ONLY",
        "publishDecision": "ALLOW_SCOPED_PUBLISHER_HANDOFF" if formal_passed else "DENY",
        "publicGetDecision": "DENY",
        "assetReport": asset_report,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diagnose pg_permissions 1.4.1 assets without formal authorization")
    parser.add_argument("--verify-assets", type=Path, help="Diagnostic-only inspection of 13 asset filenames and structures")
    parser.add_argument("--evidence", type=Path, help="Rejected: caller-supplied booleans are not authenticated evidence")
    parser.add_argument("--status", action="store_true", help="Emit current 0/7 pilot status JSON")
    args = parser.parse_args(argv)

    if args.evidence is not None:
        raise AcceptanceGateError("--evidence cannot grant acceptance from an untrusted JSON file")

    report = evaluate_pilot_status(asset_dir=args.verify_assets)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AcceptanceGateError as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)
