#!/usr/bin/env python3
"""Validate Windows Extension Landscape records stored in identities/ and v3 index.json."""
import json
import re
import sys
from datetime import date
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

try:
    from scripts import identity_records
except ModuleNotFoundError:
    import identity_records

ROOT = Path(__file__).resolve().parents[1]
INITIAL_EIGHT = {"pg_bigm", "pg_cron", "pg_hint_plan", "pgaudit", "set_user", "pg_repack", "pg_ivm", "pg_qualstats"}
NAME_RE = re.compile(r"[a-z][a-z0-9_]*")


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _format_issue(filename, issue):
    path = ".".join(map(str, issue.absolute_path))
    return f"{filename}: {path}: {issue.message}"


def validate_landscape(root=ROOT):
    root = Path(root)
    errors = []

    identity_schema = load(root / identity_records.IDENTITY_SCHEMA_REL)
    index_v3_schema = load(root / identity_records.INDEX_V3_SCHEMA_REL)
    landscape_schema = load(root / "schema" / "landscape-extension.schema.json")
    Draft202012Validator.check_schema(identity_schema)
    Draft202012Validator.check_schema(index_v3_schema)
    Draft202012Validator.check_schema(landscape_schema)

    identity_validator = Draft202012Validator(identity_schema, format_checker=FormatChecker())
    index_v3_validator = Draft202012Validator(index_v3_schema, format_checker=FormatChecker())
    landscape_validator = Draft202012Validator(landscape_schema, format_checker=FormatChecker())

    identities_dir = root / identity_records.IDENTITIES_DIR_NAME
    index_name = identity_records.INDEX_FILENAME
    idx = load(root / index_name)
    if (
        type(idx) is not dict
        or idx.get("schemaVersion") != 3
        or idx.get("identitiesDir") != identity_records.IDENTITIES_DIR_NAME
        or idx.get("packagesDir") != identity_records.PACKAGES_DIR_NAME
        or not isinstance(idx.get("extensions"), list)
        or not isinstance(idx.get("identities"), list)
    ):
        return ["Catalog v3 index format is invalid"]

    ext_names = idx["extensions"]
    id_entries = idx["identities"]
    if not all(isinstance(x, str) and NAME_RE.fullmatch(x) for x in ext_names):
        return ["Catalog v3 index format is invalid"]
    if not all(isinstance(e, dict) and isinstance(e.get("name"), str) and NAME_RE.fullmatch(e["name"]) for e in id_entries):
        return ["Catalog v3 index format is invalid"]

    if len(ext_names) != len(set(ext_names)):
        errors.append("Identities index duplicate extension names")
    id_names = [e["name"] for e in id_entries]
    if len(id_names) != len(set(id_names)):
        errors.append("Identities index duplicate identity names")

    for issue in sorted(index_v3_validator.iter_errors(idx), key=lambda err: list(err.absolute_path)):
        errors.append(_format_issue(index_name, issue))

    entries_by_name = {}
    distributed_entries = set()
    for entry in id_entries:
        entry_name = entry["name"]
        entries_by_name.setdefault(entry_name, entry)
        expected_path = f"{identity_records.IDENTITIES_DIR_NAME}/{entry_name}.json"
        if entry.get("path") != expected_path:
            errors.append(f"{index_name}: {entry_name}: unexpected identity path {entry.get('path')!r}")
        intake_class = entry.get("intakeClass")
        if intake_class == "distributed":
            distributed_entries.add(entry_name)
            if entry.get("ledgerPath") != f"{identity_records.PACKAGES_DIR_NAME}/{entry_name}.json":
                errors.append(f"{index_name}: {entry_name}: invalid ledgerPath")
        elif intake_class == "research-only":
            if "ledgerPath" in entry:
                errors.append(f"{index_name}: {entry_name}: research-only entry must not define ledgerPath")
        else:
            errors.append(f"{index_name}: {entry_name}: invalid intakeClass {intake_class!r}")

    available = set(ext_names)
    if distributed_entries != available:
        errors.append(
            f"Identities index distribution roster mismatch: "
            f"only_entries={sorted(distributed_entries - available)} only_extensions={sorted(available - distributed_entries)}"
        )

    paths = sorted(identities_dir.glob("*.json"))
    files = {p.stem for p in paths}
    if files != set(id_names):
        errors.append(
            f"Identities index and records mismatch: "
            f"only_in_index={sorted(set(id_names) - files)} only_in_records={sorted(files - set(id_names))}"
        )

    implemented = set()
    wave_orders = []
    for path in paths:
        try:
            identity = load(path)
        except (ValueError, OSError) as exc:
            errors.append(f"{path.name}: invalid JSON: {exc}")
            continue
        if type(identity) is not dict:
            errors.append(f"{path.name}: identity record must be a JSON object")
            continue

        seen_errors = set()

        def add_error(msg):
            if msg not in seen_errors:
                seen_errors.add(msg)
                errors.append(msg)

        for issue in sorted(identity_validator.iter_errors(identity), key=lambda err: list(err.absolute_path)):
            add_error(_format_issue(path.name, issue))

        name = identity.get("name")
        if name != path.stem:
            add_error(f"{path.name}: record name disagrees with filename")

        intake = identity.get("intake") if isinstance(identity.get("intake"), dict) else {}
        research = identity.get("research") if isinstance(identity.get("research"), dict) else {}
        intake_class = intake.get("class")

        entry = entries_by_name.get(path.stem)
        if entry is not None and entry.get("intakeClass") != intake_class:
            add_error(f"{path.name}: intakeClass disagrees with {index_name}")

        if intake_class == "distributed":
            status = "implemented"
            if isinstance(name, str):
                implemented.add(name)
            dist = identity.get("distribution")
            if (
                path.stem not in available
                or intake.get("distributionAllowed") is not True
                or not isinstance(dist, dict)
                or dist.get("repository") != f"pgextwin/{path.stem}"
                or dist.get("ledgerPath") != f"{identity_records.PACKAGES_DIR_NAME}/{path.stem}.json"
            ):
                add_error(f"{path.name}: invalid distribution catalog reference")
            if "status" in research:
                add_error(f"{path.name}: distributed identity research block must not define status")
        elif intake_class == "research-only":
            status = research.get("status")
            if path.stem in available or intake.get("distributionAllowed") is not False or "distribution" in identity:
                add_error(f"{path.name}: invalid distribution catalog reference")
        else:
            status = research.get("status")

        if (
            isinstance(name, str)
            and isinstance(identity.get("upstreamRepository"), str)
            and isinstance(identity.get("description"), str)
            and intake_class in ("distributed", "research-only")
            and isinstance(identity.get("research"), dict)
            and (intake_class == "distributed" or "status" in research)
        ):
            projected = identity_records.project_landscape_v1(identity)
            for issue in sorted(landscape_validator.iter_errors(projected), key=lambda err: list(err.absolute_path)):
                add_error(_format_issue(path.name, issue))

        if status == "candidate" and not str(research.get("candidateRationale", "")).strip():
            add_error(f"{path.name}: missing candidate rationale")
        if status == "not-planned":
            if not str(research.get("notPlannedReason", "")).strip():
                add_error(f"{path.name}: missing not-planned reason")
            if not research.get("windowsBinarySources"):
                add_error(f"{path.name}: not-planned requires an acquisition source")

        roadmap = research.get("roadmap")
        if isinstance(roadmap, dict):
            if status != "candidate" and not (status == "implemented" and roadmap.get("decision") == "wave-2"):
                add_error(f"{path.name}: roadmap only allowed for candidate or implemented Wave 2 history")
            if not str(roadmap.get("rationale", "")).strip():
                add_error(f"{path.name}: roadmap rationale required")
            try:
                decision_date = date.fromisoformat(roadmap.get("decisionDate", ""))
                if decision_date.isoformat() != roadmap.get("decisionDate"):
                    add_error(f"{path.name}: noncanonical decisionDate")
                if decision_date > date.today():
                    add_error(f"{path.name}: future decisionDate")
            except (ValueError, TypeError):
                add_error(f"{path.name}: malformed decisionDate")
            if roadmap.get("decision") == "wave-2":
                wave_orders.append(roadmap.get("order"))
            elif "order" in roadmap:
                add_error(f"{path.name}: non-wave roadmap must not have order")

        sources = research.get("windowsBinarySources")
        if isinstance(sources, list):
            for source in sources:
                if not isinstance(source, dict):
                    continue
                if source.get("type") not in ("upstream-official", "community", "vendor", "package-manager") or not source.get("provider"):
                    add_error(f"{path.name}: invalid source provider or type")
                if not str(source.get("url", "")).startswith("https://"):
                    add_error(f"{path.name}: source acquisition URL must be HTTPS")

        try:
            last_reviewed = date.fromisoformat(research.get("lastReviewed", ""))
            if last_reviewed > date.today():
                add_error(f"{path.name}: lastReviewed is in the future")
        except (ValueError, TypeError):
            add_error(f"{path.name}: invalid lastReviewed")

    if len(wave_orders) != 3:
        errors.append(f"Wave 2 must have exactly three records; got {len(wave_orders)}")
    if sorted(x for x in wave_orders if isinstance(x, int) and not isinstance(x, bool)) != [1, 2, 3] or len(set(map(str, wave_orders))) != len(wave_orders):
        errors.append(f"Wave 2 order must be unique and exactly [1,2,3]; got {wave_orders}")
    if not INITIAL_EIGHT.issubset(implemented):
        errors.append(f"Missing implemented initial eight: {sorted(INITIAL_EIGHT - implemented)}")
    if implemented != available:
        errors.append(f"Implemented registry and distribution catalog differ: {sorted(implemented ^ available)}")
    return errors


if __name__ == "__main__":
    failures = validate_landscape()
    for failure in failures:
        print(f"ERROR: {failure}", file=sys.stderr)
    if failures:
        sys.exit(1)
    print("Landscape Registry v1 valid (via identities/ and v3 index.json).")
