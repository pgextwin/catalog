#!/usr/bin/env python3
"""Deterministic generator for Catalog identities/<name>.json and v3 candidate index."""

from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

if __package__:
    from . import package_ledger, verified_release_record
else:
    try:
        from scripts import package_ledger, verified_release_record
    except ModuleNotFoundError:
        import package_ledger
        import verified_release_record


ROOT = Path(__file__).resolve().parents[1]
IDENTITIES_DIR_NAME = "identities"
CANDIDATE_INDEX_NAME = "index.candidate.json"
IDENTITY_SCHEMA_REL = Path("schema") / "identity.schema.json"
INDEX_V3_SCHEMA_REL = Path("schema") / "index-v3.schema.json"
FIRST_RELEASE_REGISTRY_REL = Path("config") / "first-release-registry.json"

EXPECTED_DISTRIBUTED_COUNT = 26
EXPECTED_TOTAL_COUNT = 34
KNOWN_RESEARCH_ONLY_IDS = frozenset({
    "http",
    "oracle_fdw",
    "pg_sphere",
    "pgroonga",
    "pgrouting",
    "pgvector",
    "postgis",
    "timescaledb",
})

# Partition of Catalog v2 extensions/<name>.json keys between identity-owned
# metadata and ledger-owned release/contract projections (DESIGN.md §2.1).
IDENTITY_OWNED_EXTENSION_KEYS = frozenset({
    "name",
    "displayName",
    "description",
    "upstream",
    "repository",
    "license",
    "externalSourceRegistry",
})
LEDGER_OWNED_EXTENSION_KEYS = frozenset({
    "schemaVersion",
    "upstream",
    "architecture",
    "latest",
    "postgresql",
    "runtime",
    "capabilities",
    "capabilitiesSource",
})

LANDSCAPE_SHARED_KEYS = frozenset({
    "schemaVersion",
    "name",
    "displayName",
    "description",
    "upstreamRepository",
    "pgextwinCatalogName",
})
RESEARCH_EXTRA_KEY_ORDER = (
    "status",
    "descriptionOverride",
    "lastReviewed",
    "license",
    "currentStableVersion",
    "pg18Support",
    "pg19Readiness",
    "windowsUpstreamSupport",
    "knownWindowsBinaryAvailability",
    "estimatedWindowsEffort",
    "preliminaryPriority",
    "candidateRationale",
    "reasonCode",
    "notPlannedReason",
    "notPlannedReasonJa",
    "roadmap",
    "evidenceUrls",
    "windowsBinarySources",
    "externalSourceRegistry",
)
KNOWN_LANDSCAPE_EXTRA_KEYS = frozenset(RESEARCH_EXTRA_KEY_ORDER) - {"descriptionOverride"}


def _json_path(parts) -> str:
    return ".".join(str(part) for part in parts) or "<root>"


def _validate_schema(schema: dict, instance: dict, label: str) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda err: list(err.absolute_path))
    if errors:
        details = "; ".join(f"{_json_path(err.absolute_path)}: {err.message}" for err in errors)
        raise ValueError(f"{label}: schema validation failed: {details}")


def _read_dir_records(directory: Path, label: str) -> dict[str, dict]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError(f"Missing or invalid directory: {label}")
    records: dict[str, dict] = {}
    for entry in sorted(directory.iterdir()):
        if entry.is_symlink() or not entry.is_file() or entry.suffix != ".json":
            raise ValueError(f"Unexpected non-JSON or linked entry in {label}: {entry.name}")
        stem = entry.stem
        if not package_ledger.NAME.fullmatch(stem):
            raise ValueError(f"Invalid extension filename in {label}: {entry.name}")
        records[stem] = package_ledger.read_record(entry)
    return records


def intake_metadata(name: str, first_release_sources: dict[str, str]) -> dict:
    """Return the intake classification and sealed-upstream expectation for an ID."""
    if name in verified_release_record.ALLOWED:
        return {
            "class": "distributed",
            "distributionAllowed": True,
            "registrationSource": "historical-core",
            "expectedUpstreamRepository": verified_release_record.ALLOWED[name],
            "sealedUpstream": True,
        }
    if name in first_release_sources:
        return {
            "class": "distributed",
            "distributionAllowed": True,
            "registrationSource": "first-release-registry",
            "expectedUpstreamRepository": first_release_sources[name],
            "sealedUpstream": name in verified_release_record.SEALED_FIRST_RELEASE_UPSTREAM,
        }
    if name in KNOWN_RESEARCH_ONLY_IDS:
        return {
            "class": "research-only",
            "distributionAllowed": False,
        }
    raise ValueError(f"Unknown extension ID outside distributed and known research-only sets: {name}")


def load_source_inputs(root: Path) -> dict:
    """Load and verify all existing Catalog and Landscape inputs under root."""
    root = Path(root)
    dist_index = package_ledger.read_record(root / "index.json")
    if (
        type(dist_index) is not dict
        or dist_index.get("schemaVersion") != 2
        or not isinstance(dist_index.get("extensions"), list)
    ):
        raise ValueError("Invalid index.json format (expected schemaVersion 2)")

    dist_names = dist_index["extensions"]
    if (
        not all(isinstance(name, str) and package_ledger.NAME.fullmatch(name) for name in dist_names)
        or dist_names != sorted(set(dist_names))
    ):
        raise ValueError("index.json extensions must be sorted, unique valid extension names")

    extensions = _read_dir_records(root / "extensions", "extensions/")
    packages = _read_dir_records(root / package_ledger.DIRECTORY, f"{package_ledger.DIRECTORY}/")
    dist_set = set(dist_names)
    if set(extensions) != dist_set:
        raise ValueError(
            f"extensions/ inventory differs from index.json: "
            f"only_index={sorted(dist_set - set(extensions))} "
            f"only_dir={sorted(set(extensions) - dist_set)}"
        )
    if set(packages) != dist_set:
        raise ValueError(
            f"packages/ inventory differs from index.json: "
            f"only_index={sorted(dist_set - set(packages))} "
            f"only_dir={sorted(set(packages) - dist_set)}"
        )

    if len(dist_names) != EXPECTED_DISTRIBUTED_COUNT:
        raise ValueError(
            f"Refusing identity generation: expected {EXPECTED_DISTRIBUTED_COUNT} distributed IDs, "
            f"found {len(dist_names)}"
        )

    land_index = package_ledger.read_record(root / "landscape" / "index.json")
    if (
        type(land_index) is not dict
        or land_index.get("schemaVersion") != 1
        or not isinstance(land_index.get("extensions"), list)
    ):
        raise ValueError("Invalid landscape/index.json format (expected schemaVersion 1)")

    land_names = land_index["extensions"]
    if (
        not all(isinstance(name, str) and package_ledger.NAME.fullmatch(name) for name in land_names)
        or len(land_names) != len(set(land_names))
    ):
        raise ValueError("landscape/index.json extensions must be unique valid extension names")

    landscape = _read_dir_records(root / "landscape" / "extensions", "landscape/extensions/")
    land_set = set(land_names)
    if set(landscape) != land_set:
        raise ValueError(
            f"landscape/extensions/ inventory differs from landscape/index.json: "
            f"only_index={sorted(land_set - set(landscape))} "
            f"only_dir={sorted(set(landscape) - land_set)}"
        )

    missing_landscape = sorted(dist_set - land_set)
    if missing_landscape:
        raise ValueError(f"Distributed extension(s) missing from landscape/: {missing_landscape}")

    research_only_set = land_set - dist_set
    unknown_landscape = sorted(research_only_set - KNOWN_RESEARCH_ONLY_IDS)
    if unknown_landscape:
        raise ValueError(
            "Refusing identity generation: landscape record exists for ID(s) that are neither "
            f"distributed nor known research-only entries: {unknown_landscape}"
        )

    all_ids = sorted(dist_set | land_set)
    if len(all_ids) != EXPECTED_TOTAL_COUNT or research_only_set != KNOWN_RESEARCH_ONLY_IDS:
        raise ValueError(
            f"Refusing identity generation: expected {EXPECTED_TOTAL_COUNT} total IDs "
            f"({EXPECTED_DISTRIBUTED_COUNT} distributed + {len(KNOWN_RESEARCH_ONLY_IDS)} research-only), "
            f"found {len(all_ids)} total ({len(dist_set)} distributed, {sorted(research_only_set)} research-only)"
        )

    first_release_sources, first_release_meta = verified_release_record.load_first_release_registry(
        root / FIRST_RELEASE_REGISTRY_REL
    )
    allowed_set = set(verified_release_record.ALLOWED)
    first_set = set(first_release_sources)
    if allowed_set & first_set:
        raise ValueError(f"Overlapping historical and first-release intake IDs: {sorted(allowed_set & first_set)}")
    if (allowed_set | first_set) != dist_set:
        raise ValueError(
            f"Intake roster mismatch against index.json: "
            f"missing={sorted(dist_set - (allowed_set | first_set))} "
            f"extra={sorted((allowed_set | first_set) - dist_set)}"
        )
    if research_only_set & (allowed_set | first_set):
        raise ValueError("Research-only ID must not appear in distribution intake rules")

    return {
        "all_ids": all_ids,
        "distributed_ids": dist_names,
        "research_only_ids": sorted(research_only_set),
        "extensions": extensions,
        "packages": packages,
        "landscape": landscape,
        "first_release_sources": first_release_sources,
        "first_release_meta": first_release_meta,
    }


def build_identity_record(
    name: str,
    *,
    ext_record: dict | None,
    ledger_record: dict | None,
    landscape_record: dict,
    intake_info: dict,
    first_release_entry: tuple[str, str, str] | None = None,
) -> dict:
    """Merge distribution and/or landscape records into one canonical identity record."""
    unknown_land = sorted(set(landscape_record) - (LANDSCAPE_SHARED_KEYS | KNOWN_LANDSCAPE_EXTRA_KEYS))
    if unknown_land:
        raise ValueError(f"{name}: unsupported landscape field(s) would be dropped: {unknown_land}")
    if landscape_record.get("schemaVersion") != 1 or landscape_record.get("name") != name:
        raise ValueError(f"{name}: invalid landscape schemaVersion or name")

    if intake_info["class"] == "distributed":
        if ext_record is None or ledger_record is None:
            raise ValueError(f"{name}: distributed identity requires extensions/ and packages/ records")
        if ext_record.get("schemaVersion") != 2 or ext_record.get("name") != name:
            raise ValueError(f"{name}: invalid extension record schemaVersion or name")
        if ext_record.get("repository") != f"pgextwin/{name}":
            raise ValueError(f"{name}: extension repository must be pgextwin/{name}")
        if ledger_record.get("name") != name or ledger_record.get("repository") != f"pgextwin/{name}":
            raise ValueError(f"{name}: package ledger identity mismatch")
        if ext_record != package_ledger.website_record(ledger_record):
            raise ValueError(f"{name}: extensions/{name}.json is stale relative to packages/{name}.json")

        allowed_ext_keys = IDENTITY_OWNED_EXTENSION_KEYS | LEDGER_OWNED_EXTENSION_KEYS
        unknown_ext = sorted(set(ext_record) - allowed_ext_keys)
        if unknown_ext:
            raise ValueError(f"{name}: unmapped extension field(s): {unknown_ext}")
        upstream = ext_record.get("upstream", {})
        unknown_upstream = sorted(set(upstream) - {"repository", "version", "perPostgresql"})
        if unknown_upstream:
            raise ValueError(f"{name}: unmapped upstream field(s): {unknown_upstream}")

        if landscape_record.get("status") != "implemented" or landscape_record.get("pgextwinCatalogName") != name:
            raise ValueError(f"{name}: distributed landscape record must be implemented with matching pgextwinCatalogName")
        if ext_record["displayName"] != landscape_record["displayName"]:
            raise ValueError(f"{name}: displayName differs between extensions/ and landscape/")
        expected_upstream = intake_info["expectedUpstreamRepository"]
        if upstream.get("repository") != expected_upstream or landscape_record.get("upstreamRepository") != expected_upstream:
            raise ValueError(
                f"{name}: upstream repository mismatch "
                f"(ext={upstream.get('repository')!r}, land={landscape_record.get('upstreamRepository')!r}, "
                f"expected={expected_upstream!r})"
            )
        if first_release_entry is not None:
            reg_display, reg_desc, reg_license = first_release_entry
            if (ext_record["displayName"], ext_record["description"], ext_record["license"]) != (
                reg_display,
                reg_desc,
                reg_license,
            ):
                raise ValueError(f"{name}: extension metadata differs from config/first-release-registry.json")

        identity: dict = {
            "schemaVersion": 1,
            "name": name,
        }
        if ext_record["displayName"] != name:
            identity["displayName"] = ext_record["displayName"]
        identity["upstreamRepository"] = expected_upstream
        identity["description"] = ext_record["description"]
        identity["intake"] = copy.deepcopy(intake_info)

        distribution: dict = {
            "repository": ext_record["repository"],
            "license": ext_record["license"],
            "ledgerPath": f"{package_ledger.DIRECTORY}/{name}.json",
        }
        if "externalSourceRegistry" in ext_record:
            distribution["externalSourceRegistry"] = ext_record["externalSourceRegistry"]
        identity["distribution"] = distribution

        research: dict = {}
        if landscape_record["description"] != ext_record["description"]:
            research["descriptionOverride"] = landscape_record["description"]
        for key in RESEARCH_EXTRA_KEY_ORDER:
            if key in ("status", "descriptionOverride"):
                continue
            if key in landscape_record:
                research[key] = copy.deepcopy(landscape_record[key])
        identity["research"] = research
        return identity

    if intake_info["class"] == "research-only":
        if ext_record is not None or ledger_record is not None:
            raise ValueError(f"{name}: research-only ID must not have extensions/ or packages/ records")
        if landscape_record.get("status") not in ("candidate", "not-planned"):
            raise ValueError(f"{name}: research-only status must be candidate or not-planned")
        if "pgextwinCatalogName" in landscape_record:
            raise ValueError(f"{name}: research-only record must not define pgextwinCatalogName")

        identity = {
            "schemaVersion": 1,
            "name": name,
        }
        if landscape_record["displayName"] != name:
            identity["displayName"] = landscape_record["displayName"]
        identity["upstreamRepository"] = landscape_record["upstreamRepository"]
        identity["description"] = landscape_record["description"]
        identity["intake"] = copy.deepcopy(intake_info)

        research = {}
        for key in RESEARCH_EXTRA_KEY_ORDER:
            if key == "descriptionOverride":
                continue
            if key in landscape_record:
                research[key] = copy.deepcopy(landscape_record[key])
        identity["research"] = research
        return identity

    raise ValueError(f"{name}: unsupported intake class {intake_info.get('class')!r}")


def project_landscape_v1(identity: dict) -> dict:
    """Reconstruct the exact legacy landscape/extensions/<name>.json record from an identity."""
    name = identity["name"]
    research = identity["research"]
    out: dict = {
        "schemaVersion": 1,
        "name": name,
        "displayName": identity.get("displayName", name),
        "description": research.get("descriptionOverride", identity["description"]),
        "upstreamRepository": identity["upstreamRepository"],
    }
    if identity["intake"]["class"] == "distributed":
        out["status"] = "implemented"
        out["pgextwinCatalogName"] = name
    else:
        out["status"] = research["status"]
    for key, value in research.items():
        if key in ("status", "descriptionOverride"):
            continue
        out[key] = copy.deepcopy(value)
    return out


def build_index_v3_candidate(identities_by_name: dict[str, dict]) -> dict:
    """Build the v3 candidate index pointing at identities/ and packages/."""
    distributed = []
    entries = []
    for name in sorted(identities_by_name):
        identity = identities_by_name[name]
        intake_class = identity["intake"]["class"]
        entry: dict = {
            "name": name,
            "path": f"{IDENTITIES_DIR_NAME}/{name}.json",
            "intakeClass": intake_class,
        }
        if intake_class == "distributed":
            distributed.append(name)
            entry["ledgerPath"] = identity["distribution"]["ledgerPath"]
        entries.append(entry)
    return {
        "schemaVersion": 3,
        "identitiesDir": IDENTITIES_DIR_NAME,
        "packagesDir": package_ledger.DIRECTORY,
        "extensions": distributed,
        "identities": entries,
    }


def generate_all(root: Path = ROOT) -> tuple[dict[str, dict], dict]:
    """Generate and schema-check all 34 identities and the v3 candidate index."""
    root = Path(root)
    inputs = load_source_inputs(root)
    identity_schema = package_ledger.read_record(root / IDENTITY_SCHEMA_REL)
    index_v3_schema = package_ledger.read_record(root / INDEX_V3_SCHEMA_REL)
    Draft202012Validator.check_schema(identity_schema)
    Draft202012Validator.check_schema(index_v3_schema)

    identities_by_name: dict[str, dict] = {}
    for name in inputs["all_ids"]:
        intake_info = intake_metadata(name, inputs["first_release_sources"])
        landscape_record = inputs["landscape"][name]
        identity = build_identity_record(
            name,
            ext_record=inputs["extensions"].get(name),
            ledger_record=inputs["packages"].get(name),
            landscape_record=landscape_record,
            intake_info=intake_info,
            first_release_entry=inputs["first_release_meta"].get(name),
        )
        _validate_schema(identity_schema, identity, f"{IDENTITIES_DIR_NAME}/{name}.json")
        if project_landscape_v1(identity) != landscape_record:
            raise ValueError(f"{name}: generated identity does not losslessly reconstruct landscape record")
        identities_by_name[name] = identity

    index_v3 = build_index_v3_candidate(identities_by_name)
    _validate_schema(index_v3_schema, index_v3, f"{IDENTITIES_DIR_NAME}/{CANDIDATE_INDEX_NAME}")
    return identities_by_name, index_v3


def sync_identities(root: Path = ROOT, *, check: bool = False) -> tuple[int, int]:
    """Write or verify identities/<name>.json (x34) and identities/index.candidate.json."""
    root = Path(root)
    identities_by_name, index_v3 = generate_all(root)
    identities_dir = root / IDENTITIES_DIR_NAME
    expected_bytes = {
        f"{name}.json": package_ledger.json_bytes(record)
        for name, record in identities_by_name.items()
    }
    expected_bytes[CANDIDATE_INDEX_NAME] = package_ledger.json_bytes(index_v3)

    if identities_dir.exists():
        if identities_dir.is_symlink() or not identities_dir.is_dir():
            raise ValueError(f"{IDENTITIES_DIR_NAME}/ must be a regular directory")
        actual_entries = {entry.name: entry for entry in identities_dir.iterdir()}
        unexpected = sorted(set(actual_entries) - set(expected_bytes))
        if unexpected:
            raise ValueError(f"Unexpected entry(ies) in {IDENTITIES_DIR_NAME}/: {unexpected}")
        for entry_name, entry in actual_entries.items():
            if entry.is_symlink() or not entry.is_file():
                raise ValueError(f"Non-regular file or symlink in {IDENTITIES_DIR_NAME}/: {entry_name}")

    if check:
        if not identities_dir.is_dir():
            raise ValueError(f"Missing {IDENTITIES_DIR_NAME}/ directory")
        for filename, expected in sorted(expected_bytes.items()):
            target = identities_dir / filename
            if target.is_symlink() or not target.is_file():
                raise ValueError(f"Missing generated file: {IDENTITIES_DIR_NAME}/{filename}")
            if target.read_bytes() != expected:
                raise ValueError(f"Stale generated file: {IDENTITIES_DIR_NAME}/{filename}")
        return len(identities_by_name), 0

    identities_dir.mkdir(parents=True, exist_ok=True)
    changed = 0
    for filename, expected in sorted(expected_bytes.items()):
        target = identities_dir / filename
        if not target.is_file() or target.read_bytes() != expected:
            target.write_bytes(expected)
            changed += 1
    return len(identities_by_name), changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic Catalog identities/<name>.json and candidate v3 index."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="Repository root directory (defaults to this repository).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify committed identities/ outputs match generator output without writing.",
    )
    args = parser.parse_args(argv)

    try:
        count, changed = sync_identities(args.root, check=args.check)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.check:
        print(f"Verified {count} identity files and {IDENTITIES_DIR_NAME}/{CANDIDATE_INDEX_NAME} (up to date).")
    else:
        print(f"Generated {count} identity files and {IDENTITIES_DIR_NAME}/{CANDIDATE_INDEX_NAME} ({changed} file(s) updated).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
