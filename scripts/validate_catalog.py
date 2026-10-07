#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
EXTENSION_SCHEMA_PATH = ROOT / "schema" / "extension.schema.json"
INDEX_SCHEMA_PATH = ROOT / "schema" / "index.schema.json"
INDEX_PATH = ROOT / "index.json"
EXTENSIONS_DIR = ROOT / "extensions"

FULL_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHECKSUM_LINE_RE = re.compile(r"^([0-9A-Fa-f]{64})\s+[* ]?(.+?)\s*$")
FORBIDDEN_LIFECYCLE_FIELDS = {"maintained", "maintenance", "eol", "eolDate"}
REMOTE_RETRIES = 3
REMOTE_TIMEOUT_SECONDS = 20


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def json_path(parts):
    return ".".join(str(part) for part in parts) or "<root>"


def schema_errors(schema, instance, label):
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return [
        f"{label}:{json_path(error.absolute_path)}: {error.message}"
        for error in sorted(validator.iter_errors(instance), key=lambda error: list(error.absolute_path))
    ]


def expected_release_url(record):
    return f"https://github.com/{record['repository']}/releases/tag/{record['latest']['releaseTag']}"


def expected_download_url(record, asset):
    return (
        f"https://github.com/{record['repository']}/releases/download/"
        f"{record['latest']['releaseTag']}/{asset}"
    )


def ensure_relative_package_path(value, label, errors):
    if "\\" in value:
        errors.append(f"{label}: package paths must use POSIX separators: {value}")
        return
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part == ".." for part in pure.parts):
        errors.append(f"{label}: package path must be relative without parent traversal: {value}")
    if not pure.parts or str(pure) in ("", "."):
        errors.append(f"{label}: package path must name a file: {value}")


def validate_evidence(record, major, info, errors):
    evidence = info.get("evidence")
    if not info.get("available"):
        for key in ("asset", "downloadUrl", "sha256", "evidence"):
            if key in info:
                errors.append(
                    f"postgresql.{major}: unavailable binary must not carry {key}"
                )
        return

    if not isinstance(evidence, dict):
        return

    for field in ("sbom", "vulnerabilityReport"):
        state = evidence.get(field)
        if not isinstance(state, dict):
            continue
        available = state.get("available")
        if available is True:
            asset = state.get("asset")
            if asset:
                expected = expected_download_url(record, asset)
                if state.get("downloadUrl") != expected:
                    errors.append(
                        f"postgresql.{major}.evidence.{field}.downloadUrl must be "
                        f"{expected}"
                    )
            if not SHA256_RE.fullmatch(str(state.get("sha256", ""))):
                errors.append(
                    f"postgresql.{major}.evidence.{field}.sha256 must be 64 lowercase hex"
                )
        else:
            extras = [key for key in ("asset", "downloadUrl", "sha256") if key in state]
            if extras:
                errors.append(
                    f"postgresql.{major}.evidence.{field}: unavailable evidence must "
                    f"not carry {', '.join(extras)}"
                )

    for field in ("buildProvenanceAttestation", "sbomAttestation"):
        state = evidence.get(field)
        if isinstance(state, dict):
            unexpected = sorted(set(state) - {"available"})
            if unexpected:
                errors.append(
                    f"postgresql.{major}.evidence.{field}: attestations are not "
                    f"release assets; unsupported fields: {', '.join(unexpected)}"
                )


def validate_runtime_and_capabilities(record, errors):
    runtime = record.get("runtime", {}).get("requirements", {})
    capabilities = record.get("capabilities", {})
    coverage = capabilities.get("coverage", {})
    client = runtime.get("clientExecutable", {})

    package_paths = client.get("packagePaths", [])
    for index, package_path in enumerate(package_paths):
        ensure_relative_package_path(
            package_path,
            f"runtime.requirements.clientExecutable.packagePaths[{index}]",
            errors,
        )

    if client.get("required") is True and not package_paths:
        errors.append(
            "runtime.requirements.clientExecutable: required client executable must "
            "declare at least one package path"
        )
    if client.get("required") is False and package_paths:
        errors.append(
            "runtime.requirements.clientExecutable: packagePaths must be empty when "
            "required is false"
        )

    client_coverage = coverage.get("clientExecutable")
    if client.get("required") is True and client_coverage == "not-applicable":
        errors.append(
            "capabilities.coverage.clientExecutable cannot be not-applicable when "
            "a client executable is required"
        )
    if client.get("required") is False and client_coverage not in (None, "not-applicable"):
        errors.append(
            "capabilities.coverage.clientExecutable must be not-applicable when "
            "no client executable is required"
        )
    if client_coverage == "covered" and not package_paths:
        errors.append(
            "capabilities.coverage.clientExecutable is covered but no client package path is declared"
        )

    bg = runtime.get("backgroundWorker")
    bg_coverage = coverage.get("backgroundWorker")
    if bg is False and bg_coverage not in (None, "not-applicable"):
        errors.append(
            "capabilities.coverage.backgroundWorker must be not-applicable when "
            "runtime backgroundWorker is false"
        )
    if bg is True and bg_coverage == "not-applicable":
        errors.append(
            "capabilities.coverage.backgroundWorker cannot be not-applicable when "
            "runtime backgroundWorker is true"
        )

    scenarios = capabilities.get("functionalScenarios", [])
    ids = [item.get("id") for item in scenarios if isinstance(item, dict)]
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    if duplicates:
        errors.append(
            "capabilities.functionalScenarios: duplicate functional scenario ID(s): "
            + ", ".join(duplicates)
        )


def validate_record_semantics(name, record):
    errors = []
    if record.get("schemaVersion") != 2:
        errors.append("schemaVersion must be 2")

    if record.get("name") != name:
        errors.append(
            f"name '{record.get('name')}' does not match index entry '{name}'"
        )

    if record.get("latest", {}).get("releaseUrl") != expected_release_url(record):
        errors.append(
            f"latest.releaseUrl must be {expected_release_url(record)}"
        )

    for field in FORBIDDEN_LIFECYCLE_FIELDS:
        if field in record:
            errors.append(
                f"forbidden lifecycle field '{field}' must not be stored in extension records"
            )

    postgresql = record.get("postgresql", {})
    for major, info in postgresql.items():
        if not isinstance(info, dict):
            continue
        for field in FORBIDDEN_LIFECYCLE_FIELDS:
            if field in info:
                errors.append(
                    f"postgresql.{major}: forbidden lifecycle field '{field}'; "
                    "derive maintenance status from pgextwin/build/metadata/postgresql.json"
                )

        if info.get("available") is True:
            for key in ("asset", "downloadUrl", "sha256", "evidence"):
                if key not in info:
                    errors.append(f"postgresql.{major}: available=true requires {key}")
            asset = info.get("asset")
            if asset:
                expected = expected_download_url(record, asset)
                if info.get("downloadUrl") != expected:
                    errors.append(
                        f"postgresql.{major}.downloadUrl must be {expected}"
                    )
            if not SHA256_RE.fullmatch(str(info.get("sha256", ""))):
                errors.append(
                    f"postgresql.{major}.sha256 must be 64 lowercase hex"
                )

        validate_evidence(record, major, info, errors)

    upstream = record.get("upstream", {})
    per_postgresql = upstream.get("perPostgresql")
    if isinstance(per_postgresql, dict):
        available_majors = {
            str(major)
            for major, info in postgresql.items()
            if isinstance(info, dict) and info.get("available") is True
        }
        for major in sorted(available_majors - set(per_postgresql)):
            errors.append(
                f"upstream.perPostgresql is missing available PostgreSQL major {major}"
            )

    source = record.get("capabilitiesSource", {})
    if source.get("repository") != record.get("repository"):
        errors.append(
            "capabilitiesSource.repository must match repository"
        )
    if not FULL_COMMIT_RE.fullmatch(str(source.get("commit", ""))):
        errors.append(
            "capabilitiesSource.commit must be a full 40-character lowercase hexadecimal SHA"
        )

    validate_runtime_and_capabilities(record, errors)
    return errors


def project_test_contract(contract):
    return {
        "runtimeRequirements": contract.get("runtimeRequirements"),
        "capabilities": {
            "testContractVersion": contract.get("contractVersion"),
            "coverage": contract.get("coverage"),
            "functionalScenarios": contract.get("functionalScenarios"),
        },
    }


def http_get(url, *, token=None, accept="application/vnd.github+json"):
    headers = {
        "User-Agent": "pgextwin-catalog-validator",
        "Accept": accept,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    last_error = None
    for attempt in range(REMOTE_RETRIES):
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=REMOTE_TIMEOUT_SECONDS) as response:
                return response.read(), response.headers
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_error = exc
            if attempt + 1 < REMOTE_RETRIES:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"remote request failed after {REMOTE_RETRIES} attempts: {url}: {last_error}")


def parse_checksums(data):
    text = data.decode("utf-8")
    result = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = CHECKSUM_LINE_RE.match(line)
        if not match:
            raise ValueError(f"invalid SHA256SUMS line {line_number}: {line!r}")
        digest, filename = match.groups()
        filename = filename.removeprefix("./")
        if filename in result:
            raise ValueError(f"duplicate SHA256SUMS entry: {filename}")
        result[filename] = digest.lower()
    return result


def verify_capability_source(record, token):
    source = record["capabilitiesSource"]
    encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in source["path"].split("/"))
    url = (
        f"https://raw.githubusercontent.com/{source['repository']}/"
        f"{source['commit']}/{encoded_path}"
    )
    data, _ = http_get(url, token=None, accept="application/json")
    contract = json.loads(data.decode("utf-8"))

    errors = []
    if contract.get("contractVersion") != 2:
        errors.append("source contractVersion is not 2")
    if contract.get("extension") != record["name"]:
        errors.append(
            f"source extension '{contract.get('extension')}' does not match '{record['name']}'"
        )

    projected = project_test_contract(contract)
    if record["runtime"]["requirements"] != projected["runtimeRequirements"]:
        errors.append("runtime.requirements does not match pinned Test Contract source")
    if record["capabilities"] != projected["capabilities"]:
        errors.append("capabilities does not match pinned Test Contract source")
    return errors


def verify_release(record, token):
    repository = record["repository"]
    api_url = f"https://api.github.com/repos/{repository}/releases/latest"
    payload, _ = http_get(api_url, token=token)
    release = json.loads(payload.decode("utf-8"))

    errors = []
    latest = record["latest"]
    if release.get("tag_name") != latest["releaseTag"]:
        errors.append(
            f"latest.releaseTag '{latest['releaseTag']}' is not current GitHub latest release "
            f"'{release.get('tag_name')}'"
        )
        return errors
    if release.get("published_at") != latest["publishedAt"]:
        errors.append(
            f"latest.publishedAt '{latest['publishedAt']}' does not match GitHub "
            f"'{release.get('published_at')}'"
        )
    if release.get("html_url") != latest["releaseUrl"]:
        errors.append(
            f"latest.releaseUrl '{latest['releaseUrl']}' does not match GitHub "
            f"'{release.get('html_url')}'"
        )

    assets = {asset.get("name"): asset for asset in release.get("assets", [])}
    checksums_name = latest["checksumsAsset"]
    checksums_asset = assets.get(checksums_name)
    if not checksums_asset:
        errors.append(f"release is missing checksums asset '{checksums_name}'")
        return errors

    try:
        checksum_bytes, _ = http_get(
            checksums_asset["browser_download_url"],
            token=None,
            accept="text/plain",
        )
        checksums = parse_checksums(checksum_bytes)
    except Exception as exc:
        errors.append(f"could not read published {checksums_name}: {exc}")
        return errors

    for major, info in record["postgresql"].items():
        if info.get("available") is not True:
            continue
        asset_name = info["asset"]
        release_asset = assets.get(asset_name)
        if not release_asset:
            errors.append(f"PostgreSQL {major}: release asset missing: {asset_name}")
            continue
        if release_asset.get("browser_download_url") != info["downloadUrl"]:
            errors.append(
                f"PostgreSQL {major}: downloadUrl does not match GitHub release asset URL"
            )
        checksum = checksums.get(asset_name)
        if checksum != info["sha256"]:
            errors.append(
                f"PostgreSQL {major}: sha256 '{info['sha256']}' does not match "
                f"published {checksums_name} value '{checksum}'"
            )
        github_digest = release_asset.get("digest")
        if github_digest and github_digest != f"sha256:{info['sha256']}":
            errors.append(
                f"PostgreSQL {major}: GitHub release asset digest '{github_digest}' "
                f"does not match catalog sha256"
            )

        evidence = info["evidence"]
        for field, suffix in (
            ("sbom", ".spdx.json"),
            ("vulnerabilityReport", ".vulnerabilities.json"),
        ):
            state = evidence[field]
            expected_asset = asset_name.removesuffix(".zip") + suffix
            actual_present = expected_asset in assets
            if state["available"] is False and actual_present:
                errors.append(
                    f"PostgreSQL {major}: evidence.{field}.available=false but "
                    f"release asset exists: {expected_asset}"
                )
            if state["available"] is True:
                if state["asset"] not in assets:
                    errors.append(
                        f"PostgreSQL {major}: evidence.{field} asset missing from release: "
                        f"{state['asset']}"
                    )
                elif checksums.get(state["asset"]) != state["sha256"]:
                    errors.append(
                        f"PostgreSQL {major}: evidence.{field} sha256 does not match "
                        f"published {checksums_name}"
                    )
    return errors


def validate_catalog(verify_remote=False):
    extension_schema = load_json(EXTENSION_SCHEMA_PATH)
    index_schema = load_json(INDEX_SCHEMA_PATH)
    Draft202012Validator.check_schema(extension_schema)
    Draft202012Validator.check_schema(index_schema)

    index = load_json(INDEX_PATH)
    errors = schema_errors(index_schema, index, "index.json")

    if index.get("schemaVersion") != 2:
        errors.append("index.json: schemaVersion must be 2")

    names = index.get("extensions")
    if not isinstance(names, list):
        names = []

    records = {}
    for name in names:
        path = EXTENSIONS_DIR / f"{name}.json"
        if not path.is_file():
            errors.append(f"index.json references missing file: {path.relative_to(ROOT)}")
            continue

        record = load_json(path)
        records[name] = record
        errors.extend(
            schema_errors(extension_schema, record, str(path.relative_to(ROOT)))
        )
        errors.extend(
            f"{path.relative_to(ROOT)}: {message}"
            for message in validate_record_semantics(name, record)
        )

    if EXTENSIONS_DIR.exists():
        indexed = set(names)
        for path in sorted(EXTENSIONS_DIR.glob("*.json")):
            if path.stem not in indexed:
                errors.append(
                    f"extensions/{path.name} exists but is not listed in index.json"
                )

    if verify_remote:
        token = os.environ.get("GITHUB_TOKEN")
        for name, record in records.items():
            try:
                source_errors = verify_capability_source(record, token)
                errors.extend(
                    f"extensions/{name}.json: remote capability source: {message}"
                    for message in source_errors
                )
            except Exception as exc:
                errors.append(
                    f"extensions/{name}.json: remote capability source verification failed: {exc}"
                )

            try:
                release_errors = verify_release(record, token)
                errors.extend(
                    f"extensions/{name}.json: remote release verification: {message}"
                    for message in release_errors
                )
            except Exception as exc:
                errors.append(
                    f"extensions/{name}.json: remote release verification failed: {exc}"
                )

    return errors, len(records)


def main():
    parser = argparse.ArgumentParser(description="Validate pgextwin Catalog schema v2.")
    parser.add_argument(
        "--verify-remote",
        action="store_true",
        help=(
            "Verify pinned Test Contract snapshots and current GitHub Release metadata, "
            "including the published SHA256SUMS.txt values."
        ),
    )
    args = parser.parse_args()

    errors, count = validate_catalog(verify_remote=args.verify_remote)
    if errors:
        for message in errors:
            print(message, file=sys.stderr)
        print(f"Catalog validation failed with {len(errors)} error(s).", file=sys.stderr)
        return 1

    remote_suffix = " with remote provenance/release verification" if args.verify_remote else ""
    print(f"Catalog schema v2 validation passed for {count} extension record(s){remote_suffix}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
