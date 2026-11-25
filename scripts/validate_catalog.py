#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

try:
    from scripts import identity_records, package_ledger, verified_release_record
    from scripts.release_inventory import match_zip, release_assets
except ModuleNotFoundError:
    import identity_records
    import package_ledger
    import verified_release_record
    from release_inventory import match_zip, release_assets

ROOT = Path(__file__).resolve().parents[1]
EXTENSION_SCHEMA_PATH = ROOT / "schema" / "extension.schema.json"
LEDGER_SCHEMA_PATH = ROOT / "schema" / "package-ledger.schema.json"
LEDGER_DIR = ROOT / package_ledger.DIRECTORY
INDEX_PATH = ROOT / identity_records.INDEX_FILENAME
IDENTITY_SCHEMA_REL = identity_records.IDENTITY_SCHEMA_REL
INDEX_V3_SCHEMA_REL = identity_records.INDEX_V3_SCHEMA_REL

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



def read_public_release_checksums(repository, tag, checksums_asset):
    """Read actual anonymous public bytes; REST asset fallback is *not* metadata proof.

    Preserve the original public URL as the primary path. Only 502/503/504
    gateway errors can trigger the separate GitHub API asset-byte route.
    Never turn a 401/403/404, corrupt payload, or incorrect digest into success.
    """
    name = checksums_asset.get("name")
    canonical_url = f"https://github.com/{repository}/releases/download/{tag}/{name}"
    if checksums_asset.get("browser_download_url") != canonical_url:
        raise ValueError("published checksums asset URL is not canonical")
    size = checksums_asset.get("size")
    if type(size) is not int or not (0 < size <= 1024 * 1024):
        raise ValueError("invalid published checksums asset size")
    digest = checksums_asset.get("digest")
    if digest is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", str(digest)):
        raise ValueError("invalid GitHub checksums asset digest")

    try:
        raw, headers = http_get(canonical_url, token=None, accept="text/plain")
    except RuntimeError as primary_error:
        if not re.search(r"HTTP Error (?:502|503|504)\b", str(primary_error)):
            raise
        asset_id = checksums_asset.get("id")
        if type(asset_id) is not int or asset_id < 1:
            raise ValueError("invalid release asset ID for byte fallback") from primary_error
        api_url = f"https://api.github.com/repos/{repository}/releases/assets/{asset_id}"
        raw, headers = http_get(api_url, token=None, accept="application/octet-stream")
        if "json" in str(headers.get("Content-Type", "")).lower():
            raise ValueError("GitHub REST fallback returned JSON metadata, not asset bytes")

    if len(raw) != size:
        raise ValueError("actual published checksums asset byte length differs from GitHub release")
    if digest and hashlib.sha256(raw).hexdigest() != digest.removeprefix("sha256:"):
        raise ValueError("actual published checksums asset SHA256 differs from GitHub release")
    return parse_checksums(raw)

def verify_release(record, token, pinned=None):
    repository = record["repository"]
    latest = record["latest"]
    tag = latest["releaseTag"]
    # The Catalog records the latest *authorized* Release, not necessarily the
    # newest publicly visible Release. A newer failed scheduled Publisher run
    # must NOT force unsafe Catalog admission or block unrelated protected PRs.
    # Recheck the exact stored public tag, its assets and published checksums.
    if not re.fullmatch(r"v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*", tag):
        return ["unsafe Catalog-pinned Release tag"]
    api_url = f"https://api.github.com/repos/{repository}/releases/tags/{tag}"
    payload, _ = http_get(api_url, token=token)
    release = json.loads(payload.decode("utf-8"))

    errors = []
    if release.get("tag_name") != tag:
        errors.append(
            f"Catalog-pinned releaseTag '{tag}' does not match GitHub "
            f"'{release.get('tag_name')}'"
        )
        return errors
    if release.get("draft") is not False or release.get("prerelease") is not False:
        errors.append("Catalog-pinned Release must be public and stable")
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
    if pinned is not None:
        try:
            release_id, release_inventory = release_assets(repository, tag, release)
            if release_id != pinned["releaseId"]:
                raise ValueError("ledger Release ID differs from public Release")
            for package in pinned["packages"]:
                match_zip(repository, tag, package["pgMajor"], package, release_inventory)
        except ValueError as exc:
            errors.append(f"ledger Release/ZIP pins: {exc}")
    checksums_name = latest["checksumsAsset"]
    checksums_asset = assets.get(checksums_name)
    if not checksums_asset:
        errors.append(f"release is missing checksums asset '{checksums_name}'")
        return errors

    try:
        checksums = read_public_release_checksums(repository, tag, checksums_asset)
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


def _compare_mapping_fields(label: str, actual: dict, expected: dict, errors: list[str]) -> None:
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    if missing:
        errors.append(f"{label}: dropped field(s): {', '.join(missing)}")
    if extra:
        errors.append(f"{label}: unexpected extra field(s): {', '.join(extra)}")
    for key in sorted(set(expected) & set(actual)):
        if actual[key] != expected[key]:
            errors.append(
                f"{label}.{key}: value mismatch (actual={actual[key]!r}, expected={expected[key]!r})"
            )


def validate_identities(root=ROOT):
    """Validate root v3 index.json, identities/*.json, intake rules, and landscape projection."""
    root = Path(root)
    errors = []

    try:
        identity_schema = package_ledger.read_record(root / IDENTITY_SCHEMA_REL)
        index_v3_schema = package_ledger.read_record(root / INDEX_V3_SCHEMA_REL)
        Draft202012Validator.check_schema(identity_schema)
        Draft202012Validator.check_schema(index_v3_schema)
    except Exception as exc:
        return [f"identities schema error: {exc}"]

    index_name = identity_records.INDEX_FILENAME
    index_path = root / index_name
    index = None
    if index_path.is_symlink() or not index_path.is_file():
        errors.append(f"Missing or invalid {index_name}")
    else:
        try:
            index = package_ledger.read_record(index_path)
            errors.extend(schema_errors(index_v3_schema, index, index_name))
        except (ValueError, KeyError, TypeError, OSError) as exc:
            errors.append(f"{index_name}: {exc}")

    identities_dir = root / identity_records.IDENTITIES_DIR_NAME
    if identities_dir.is_symlink() or not identities_dir.is_dir():
        errors.append(f"missing or invalid {identity_records.IDENTITIES_DIR_NAME}/ directory")
        return errors

    actual_stems = set()
    for entry in sorted(identities_dir.iterdir()):
        if (
            entry.is_symlink()
            or not entry.is_file()
            or entry.suffix != ".json"
            or not package_ledger.NAME.fullmatch(entry.stem)
        ):
            errors.append(
                f"{identity_records.IDENTITIES_DIR_NAME}/{entry.name}: "
                "unexpected file, link, or invalid identity filename"
            )
            continue
        actual_stems.add(entry.stem)

    index_entries = index.get("identities") if isinstance(index, dict) and isinstance(index.get("identities"), list) else []
    expected_stems = {
        entry["name"]
        for entry in index_entries
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    dist_roster = set(index["extensions"]) if isinstance(index, dict) and isinstance(index.get("extensions"), list) else set()

    missing_files = sorted(expected_stems - actual_stems)
    extra_files = sorted(actual_stems - expected_stems) if expected_stems else []
    if missing_files:
        errors.append(
            f"{identity_records.IDENTITIES_DIR_NAME}/ missing file(s): "
            + ", ".join(f"{name}.json" for name in missing_files)
        )
    if extra_files:
        errors.append(
            f"{identity_records.IDENTITIES_DIR_NAME}/ unexpected file(s): "
            + ", ".join(f"{name}.json" for name in extra_files)
        )

    loaded_identities = {}
    historical_core_names = set()
    first_release_names = set()

    for name in sorted(actual_stems):
        rel_path = f"{identity_records.IDENTITIES_DIR_NAME}/{name}.json"
        id_path = identities_dir / f"{name}.json"
        try:
            identity = package_ledger.read_record(id_path)
        except (ValueError, OSError) as exc:
            errors.append(f"{rel_path}: {exc}")
            continue

        loaded_identities[name] = identity
        errors.extend(schema_errors(identity_schema, identity, rel_path))

        if identity.get("name") != name:
            errors.append(f"{rel_path}: name {identity.get('name')!r} does not match filename '{name}'")
        if "displayName" in identity and identity["displayName"] == name:
            errors.append(f"{rel_path}: displayName must be omitted when equal to name")

        intake = identity.get("intake")
        research = identity.get("research")
        pkg_path = root / package_ledger.DIRECTORY / f"{name}.json"

        if isinstance(intake, dict):
            intake_class = intake.get("class")
            if intake_class == "distributed":
                reg_source = intake.get("registrationSource")
                expected_upstream = intake.get("expectedUpstreamRepository")
                sealed = intake.get("sealedUpstream")
                if intake.get("distributionAllowed") is not True:
                    errors.append(f"{rel_path}.intake: distributed identity must set distributionAllowed=true")
                if expected_upstream != identity.get("upstreamRepository"):
                    errors.append(
                        f"{rel_path}.intake: expectedUpstreamRepository disagrees with upstreamRepository"
                    )
                if reg_source == "historical-core":
                    historical_core_names.add(name)
                    if (
                        name not in verified_release_record.ALLOWED
                        or sealed is not True
                        or expected_upstream != verified_release_record.ALLOWED.get(name)
                    ):
                        errors.append(
                            f"{rel_path}.intake: historical-core identity failed sealed registration rules"
                        )
                elif reg_source == "first-release-registry":
                    first_release_names.add(name)
                    if name in verified_release_record.ALLOWED:
                        errors.append(
                            f"{rel_path}.intake: historical-core extension cannot use first-release-registry"
                        )
                    if name in verified_release_record.SEALED_FIRST_RELEASE_UPSTREAM:
                        if (
                            sealed is not True
                            or expected_upstream != verified_release_record.SEALED_FIRST_RELEASE_UPSTREAM[name]
                        ):
                            errors.append(
                                f"{rel_path}.intake: sealed first-release upstream constraint violated"
                            )
                else:
                    errors.append(f"{rel_path}.intake: invalid registrationSource {reg_source!r}")

                dist = identity.get("distribution")
                if not isinstance(dist, dict):
                    errors.append(f"{rel_path}.distribution: missing object on distributed identity")
                else:
                    if dist.get("repository") != f"pgextwin/{name}":
                        errors.append(f"{rel_path}.distribution.repository: must be pgextwin/{name}")
                    if dist.get("ledgerPath") != f"{package_ledger.DIRECTORY}/{name}.json":
                        errors.append(
                            f"{rel_path}.distribution.ledgerPath: must be {package_ledger.DIRECTORY}/{name}.json"
                        )
                    if not isinstance(dist.get("license"), str) or not dist["license"].strip():
                        errors.append(f"{rel_path}.distribution.license: must be non-empty")

                if isinstance(research, dict):
                    if "status" in research:
                        errors.append(f"{rel_path}.research: distributed identity must not define status")
                    if "descriptionOverride" in research:
                        override = research["descriptionOverride"]
                        if (
                            not isinstance(override, str)
                            or not override.strip()
                            or override == identity.get("description")
                        ):
                            errors.append(
                                f"{rel_path}.research.descriptionOverride: must be non-empty and differ from description"
                            )
                    if name in identity_records.DESCRIPTION_OVERRIDE_IDS:
                        desc = identity.get("description")
                        override = research.get("descriptionOverride")
                        if (
                            not isinstance(desc, str)
                            or not desc.strip()
                            or not isinstance(override, str)
                            or not override.strip()
                            or override == desc
                        ):
                            errors.append(
                                f"{rel_path}.research.descriptionOverride: must preserve differing description override"
                            )
                if isinstance(index, dict) and name not in dist_roster:
                    errors.append(f"{rel_path} is distributed but is not listed in {index_name}")

            elif intake_class == "research-only":
                if intake.get("distributionAllowed") is not False:
                    errors.append(f"{rel_path}.intake: research-only identity must set distributionAllowed=false")
                if "distribution" in identity:
                    errors.append(f"{rel_path}: research-only identity must not define distribution")
                if (
                    name in verified_release_record.ALLOWED
                    or name in verified_release_record.SEALED_FIRST_RELEASE_UPSTREAM
                ):
                    errors.append(f"{rel_path}.intake: registered distributed extension cannot be research-only")
                if pkg_path.exists() or pkg_path.is_symlink():
                    errors.append(
                        f"{rel_path}: research-only identity must not have {package_ledger.DIRECTORY}/ file"
                    )
                if isinstance(research, dict) and "descriptionOverride" in research:
                    errors.append(
                        f"{rel_path}.research.descriptionOverride: forbidden on research-only identity"
                    )
                if isinstance(index, dict) and name in dist_roster:
                    errors.append(
                        f"{rel_path}: listed in {index_name} extensions but intake.class is 'research-only'"
                    )
            else:
                errors.append(f"{rel_path}.intake: unknown class {intake_class!r}")

        if isinstance(intake, dict) and isinstance(research, dict):
            try:
                identity_records.project_landscape_v1(identity)
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(f"{rel_path}: failed landscape reconstruction: {exc}")

    missing_core = sorted(set(verified_release_record.ALLOWED) - historical_core_names)
    if missing_core:
        errors.append(
            f"{identity_records.IDENTITIES_DIR_NAME}/: missing historical-core identity(ies): "
            + ", ".join(missing_core)
        )
    missing_sealed = sorted(set(verified_release_record.SEALED_FIRST_RELEASE_UPSTREAM) - first_release_names)
    if missing_sealed:
        errors.append(
            f"{identity_records.IDENTITIES_DIR_NAME}/: missing sealed first-release identity(ies): "
            + ", ".join(missing_sealed)
        )
    if not (3 <= len(first_release_names) <= 128 - len(verified_release_record.ALLOWED)):
        errors.append(
            f"{identity_records.IDENTITIES_DIR_NAME}/: invalid first-release identity count ({len(first_release_names)})"
        )
    missing_override_ids = sorted(identity_records.DESCRIPTION_OVERRIDE_IDS - set(loaded_identities))
    if missing_override_ids:
        errors.append(
            f"{identity_records.IDENTITIES_DIR_NAME}/: missing descriptionOverride identity(ies): "
            + ", ".join(missing_override_ids)
        )

    can_build_index = all(
        isinstance(doc.get("intake"), dict)
        and isinstance(doc["intake"].get("class"), str)
        and (
            doc["intake"].get("class") != "distributed"
            or (
                isinstance(doc.get("distribution"), dict)
                and isinstance(doc["distribution"].get("ledgerPath"), str)
            )
        )
        for doc in loaded_identities.values()
    )
    if (
        isinstance(index, dict)
        and loaded_identities
        and set(loaded_identities) == actual_stems
        and can_build_index
    ):
        expected_index = identity_records.build_index_v3(
            loaded_identities, packages_dir=package_ledger.DIRECTORY
        )
        _compare_mapping_fields(index_name, index, expected_index, errors)

    return errors


def validate_identity_distribution(name: str, identity: dict, projected: dict) -> list[str]:
    """Cross-check identity-owned distribution fields against the ledger-projected v2 record."""
    rel_path = f"{identity_records.IDENTITIES_DIR_NAME}/{name}.json"
    errors: list[str] = []

    if identity.get("name") != name or projected.get("name") != name:
        errors.append(f"{rel_path}: identity/ledger name mismatch for {name}")

    intake = identity.get("intake")
    if (
        not isinstance(intake, dict)
        or intake.get("class") != "distributed"
        or intake.get("distributionAllowed") is not True
        or intake.get("expectedUpstreamRepository") != identity.get("upstreamRepository")
    ):
        errors.append(f"{rel_path}.intake: invalid distributed intake metadata")

    dist = identity.get("distribution")
    if not isinstance(dist, dict):
        errors.append(f"{rel_path}.distribution: missing object on distributed identity")
        return errors

    if identity.get("displayName", name) != projected.get("displayName"):
        errors.append(
            f"{rel_path}.displayName: differs from {package_ledger.DIRECTORY}/{name}.json "
            f"({identity.get('displayName', name)!r} != {projected.get('displayName')!r})"
        )
    if identity.get("description") != projected.get("description"):
        errors.append(
            f"{rel_path}.description: differs from {package_ledger.DIRECTORY}/{name}.json"
        )
    if identity.get("upstreamRepository") != projected.get("upstream", {}).get("repository"):
        errors.append(
            f"{rel_path}.upstreamRepository: differs from {package_ledger.DIRECTORY}/{name}.json"
        )

    expected_repo = f"pgextwin/{name}"
    if dist.get("repository") != projected.get("repository") or dist.get("repository") != expected_repo:
        errors.append(
            f"{rel_path}.distribution.repository: differs from {package_ledger.DIRECTORY}/{name}.json"
        )
    if dist.get("license") != projected.get("license"):
        errors.append(
            f"{rel_path}.distribution.license: differs from {package_ledger.DIRECTORY}/{name}.json"
        )
    expected_ledger = f"{package_ledger.DIRECTORY}/{name}.json"
    if dist.get("ledgerPath") != expected_ledger:
        errors.append(f"{rel_path}.distribution.ledgerPath: must be {expected_ledger}")
    if ("externalSourceRegistry" in dist) != ("externalSourceRegistry" in projected) or (
        dist.get("externalSourceRegistry") != projected.get("externalSourceRegistry")
    ):
        errors.append(
            f"{rel_path}.distribution.externalSourceRegistry: differs from {package_ledger.DIRECTORY}/{name}.json"
        )
    return errors


def validate_catalog(verify_remote=False, root=ROOT):
    root = Path(root)
    extension_schema = load_json(root / "schema" / "extension.schema.json")
    ledger_schema = load_json(root / "schema" / "package-ledger.schema.json")
    identity_schema = load_json(root / IDENTITY_SCHEMA_REL)
    index_v3_schema = load_json(root / INDEX_V3_SCHEMA_REL)
    registry = Registry().with_resource(extension_schema["$id"], Resource.from_contents(extension_schema))
    ledger_validator = Draft202012Validator(ledger_schema, registry=registry,
                                            format_checker=FormatChecker())
    Draft202012Validator.check_schema(extension_schema)
    Draft202012Validator.check_schema(ledger_schema)
    Draft202012Validator.check_schema(identity_schema)
    Draft202012Validator.check_schema(index_v3_schema)

    index_name = identity_records.INDEX_FILENAME
    index_path = root / index_name
    errors = []
    index = {}
    if index_path.is_symlink() or not index_path.is_file():
        errors.append(f"Missing or invalid {index_name}")
    else:
        try:
            index = package_ledger.read_record(index_path)
            errors.extend(schema_errors(index_v3_schema, index, index_name))
        except (ValueError, KeyError, TypeError, OSError) as exc:
            errors.append(f"{index_name}: {exc}")

    if isinstance(index, dict) and index:
        if index.get("schemaVersion") != 3:
            errors.append(f"{index_name}: schemaVersion must be 3")
        if index.get("identitiesDir") != identity_records.IDENTITIES_DIR_NAME:
            errors.append(f"{index_name}: identitiesDir must be {identity_records.IDENTITIES_DIR_NAME!r}")
        if index.get("packagesDir") != package_ledger.DIRECTORY:
            errors.append(f"{index_name}: packagesDir must be {package_ledger.DIRECTORY!r}")

    names = index.get("extensions") if isinstance(index, dict) else []
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        names = []

    ledger_dir = root / package_ledger.DIRECTORY
    identities_dir = root / identity_records.IDENTITIES_DIR_NAME
    records = {}
    if ledger_dir.is_symlink() or not ledger_dir.is_dir():
        errors.append(f"missing or invalid {package_ledger.DIRECTORY}/ directory")
    elif sorted(path.stem for path in ledger_dir.glob("*.json")) != sorted(names):
        errors.append(f"{package_ledger.DIRECTORY}/ inventory differs from {index_name}")

    for name in names:
        id_rel = f"{identity_records.IDENTITIES_DIR_NAME}/{name}.json"
        id_path = identities_dir / f"{name}.json"
        if id_path.is_symlink() or not id_path.is_file():
            errors.append(f"{index_name} references missing identity file: {id_rel}")
            continue
        try:
            identity = package_ledger.read_record(id_path)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            errors.append(f"{id_rel}: {exc}")
            continue

        try:
            ledger_path = ledger_dir / f"{name}.json"
            ledger = package_ledger.read_record(ledger_path)
            ledger_validator.validate(ledger)
            record = package_ledger.website_record(ledger)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            errors.append(f"{package_ledger.DIRECTORY}/{name}.json: {exc}")
            continue
        except ValidationError as exc:
            errors.append(f"{package_ledger.DIRECTORY}/{name}.json:{json_path(exc.path)}: {exc.message}")
            continue

        errors.extend(validate_identity_distribution(name, identity, record))
        records[name] = (record, package_ledger.current_release(ledger))
        errors.extend(
            schema_errors(extension_schema, record, f"{package_ledger.DIRECTORY}/{name}.json")
        )
        errors.extend(
            f"{package_ledger.DIRECTORY}/{name}.json: {message}"
            for message in validate_record_semantics(name, record)
        )

    errors.extend(validate_identities(root))
    errors = list(dict.fromkeys(errors))

    if verify_remote:
        token = os.environ.get("GITHUB_TOKEN")
        for name, (record, pinned) in records.items():
            try:
                source_errors = verify_capability_source(record, token)
                errors.extend(
                    f"{package_ledger.DIRECTORY}/{name}.json: remote capability source: {message}"
                    for message in source_errors
                )
            except Exception as exc:
                errors.append(
                    f"{package_ledger.DIRECTORY}/{name}.json: remote capability source verification failed: {exc}"
                )

            try:
                release_errors = verify_release(record, token, pinned)
                errors.extend(
                    f"{package_ledger.DIRECTORY}/{name}.json: remote release verification: {message}"
                    for message in release_errors
                )
            except Exception as exc:
                errors.append(
                    f"{package_ledger.DIRECTORY}/{name}.json: remote release verification failed: {exc}"
                )

    return errors, len(records)


def main():
    parser = argparse.ArgumentParser(description="Validate pgextwin Catalog schema v3.")
    parser.add_argument(
        "--verify-remote",
        action="store_true",
        help=(
            "Verify pinned Test Contract snapshots and the exact Catalog-approved public Release, "
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
    print(f"Catalog schema v3 validation passed for {count} extension record(s){remote_suffix}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
