#!/usr/bin/env python3
"""Validate independent Windows Extension Landscape records; do not alter distribution Catalog v2."""
import json
import re
import sys
from pathlib import Path
from datetime import date
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
INITIAL_EIGHT = {"pg_bigm", "pg_cron", "pg_hint_plan", "pgaudit", "set_user", "pg_repack", "pg_ivm", "pg_qualstats"}

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def validate_landscape(root=ROOT):
    root = Path(root)
    errors = []
    schema = load(root / "schema" / "landscape-extension.schema.json")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    idx = load(root / "landscape" / "index.json")
    names = idx.get("extensions", [])
    if idx.get("schemaVersion") != 1 or not isinstance(names, list) or not all(isinstance(x, str) and re.fullmatch(r"[a-z][a-z0-9_]*", x) for x in names):
        return ["Landscape index format is invalid"]
    if len(names) != len(set(names)):
        errors.append("Landscape index duplicate names")
    paths = sorted((root / "landscape" / "extensions").glob("*.json"))
    files = {p.stem for p in paths}
    if files != set(names):
        errors.append(f"Landscape index and records mismatch: only_in_index={sorted(set(names)-files)} only_in_records={sorted(files-set(names))}")
    dist_index = load(root / "index.json")
    available = set(dist_index.get("extensions", []))
    implemented = set()
    wave_orders = []
    roadmap_seen = 0
    for path in paths:
        try:
            record = load(path)
        except (ValueError, OSError) as exc:
            errors.append(f"{path.name}: invalid JSON: {exc}")
            continue
        for issue in validator.iter_errors(record):
            errors.append(f"{path.name}: {'.'.join(map(str, issue.absolute_path))}: {issue.message}")
        name = record.get("name")
        if name != path.stem:
            errors.append(f"{path.name}: record name disagrees with filename")
        if record.get("status") == "implemented":
            implemented.add(name)
            if record.get("pgextwinCatalogName") not in available or record.get("pgextwinCatalogName") != name:
                errors.append(f"{path.name}: invalid distribution catalog reference")
        if record.get("status") == "candidate" and not str(record.get("candidateRationale", "")).strip():
            errors.append(f"{path.name}: missing candidate rationale")
        if record.get("status") == "not-planned":
            if not str(record.get("notPlannedReason", "")).strip():
                errors.append(f"{path.name}: missing not-planned reason")
            if not record.get("windowsBinarySources"):
                errors.append(f"{path.name}: not-planned requires an acquisition source")
        roadmap = record.get("roadmap")
        if roadmap is not None:
            roadmap_seen += 1
            if record.get("status") != "candidate":
                errors.append(f"{path.name}: roadmap only allowed for candidate")
            if not str(roadmap.get("rationale", "")).strip():
                errors.append(f"{path.name}: roadmap rationale required")
            try:
                decision_date = date.fromisoformat(roadmap.get("decisionDate", ""))
                if decision_date.isoformat() != roadmap.get("decisionDate"):
                    errors.append(f"{path.name}: noncanonical decisionDate")
                if decision_date > date.today():
                    errors.append(f"{path.name}: future decisionDate")
            except (ValueError, TypeError):
                errors.append(f"{path.name}: malformed decisionDate")
            if roadmap.get("decision") == "wave-2":
                wave_orders.append(roadmap.get("order"))
            elif "order" in roadmap:
                errors.append(f"{path.name}: non-wave roadmap must not have order")
        for source in record.get("windowsBinarySources", []):
            if source.get("type") not in ("upstream-official", "community", "vendor", "package-manager") or not source.get("provider"):
                errors.append(f"{path.name}: invalid source provider or type")
            if not str(source.get("url", "")).startswith("https://"):
                errors.append(f"{path.name}: source acquisition URL must be HTTPS")
        try:
            last_reviewed = date.fromisoformat(record.get("lastReviewed", ""))
            if last_reviewed > date.today():
                errors.append(f"{path.name}: lastReviewed is in the future")
        except (ValueError, TypeError):
            errors.append(f"{path.name}: invalid lastReviewed")
    if roadmap_seen:
        if len(wave_orders) != 3:
            errors.append(f"Wave 2 must have exactly three records; got {len(wave_orders)}")
        if sorted(x for x in wave_orders if isinstance(x, int)) != [1, 2, 3] or len(set(map(str, wave_orders))) != len(wave_orders):
            errors.append(f"Wave 2 order must be unique and exactly [1,2,3]; got {wave_orders}")
    if not INITIAL_EIGHT.issubset(implemented):
        errors.append(f"Missing implemented initial eight: {sorted(INITIAL_EIGHT-implemented)}")
    if implemented != available:
        errors.append(f"Implemented registry and distribution catalog differ: {sorted(implemented ^ available)}")
    return errors

if __name__ == "__main__":
    failures = validate_landscape()
    for failure in failures:
        print(f"ERROR: {failure}", file=sys.stderr)
    if failures:
        sys.exit(1)
    print("Landscape Registry v1 valid; distribution Catalog v2 remains independent.")
