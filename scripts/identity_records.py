#!/usr/bin/env python3
"""Stdlib-only helpers for Catalog identities/<name>.json and v3 index.json."""

from __future__ import annotations

import copy
from pathlib import Path

IDENTITIES_DIR_NAME = "identities"
INDEX_FILENAME = "index.json"
PACKAGES_DIR_NAME = "packages"
IDENTITY_SCHEMA_REL = Path("schema") / "identity.schema.json"
INDEX_V3_SCHEMA_REL = Path("schema") / "index-v3.schema.json"

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

# The 12 distributed extensions whose Landscape summary intentionally differs
# from their distribution description and must keep research.descriptionOverride.
DESCRIPTION_OVERRIDE_IDS = frozenset({
    "orafce",
    "pg_bigm",
    "pg_cron",
    "pg_hint_plan",
    "pg_ivm",
    "pg_partman",
    "pg_qualstats",
    "pg_repack",
    "pg_stat_monitor",
    "pgaudit",
    "plpgsql_check",
    "set_user",
})


def project_landscape_v1(identity: dict) -> dict:
    """Reconstruct the v1 Landscape record view from a canonical identity record."""
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


def build_index_v3(
    identities_by_name: dict[str, dict],
    packages_dir: str = PACKAGES_DIR_NAME,
) -> dict:
    """Build the canonical v3 root index.json structure from loaded identities."""
    distributed: list[str] = []
    entries: list[dict] = []
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
        "packagesDir": packages_dir,
        "extensions": distributed,
        "identities": entries,
    }
