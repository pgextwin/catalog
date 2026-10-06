import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "extension.schema.json"
INDEX_PATH = ROOT / "index.json"
EXTENSIONS_DIR = ROOT / "extensions"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    schema = load_json(SCHEMA_PATH)
    validator = Draft202012Validator(schema)
    index = load_json(INDEX_PATH)

    if index.get("schemaVersion") != 1:
        print("index.json: schemaVersion must be 1", file=sys.stderr)
        return 1

    names = index.get("extensions")
    if not isinstance(names, list) or len(names) != len(set(names)):
        print("index.json: extensions must be a unique array", file=sys.stderr)
        return 1

    errors = 0

    for name in names:
        path = EXTENSIONS_DIR / f"{name}.json"
        if not path.is_file():
            print(f"index.json references missing file: {path.relative_to(ROOT)}", file=sys.stderr)
            errors += 1
            continue

        record = load_json(path)
        validation_errors = sorted(validator.iter_errors(record), key=lambda error: list(error.path))
        for error in validation_errors:
            location = ".".join(str(part) for part in error.path) or "<root>"
            print(f"{path.relative_to(ROOT)}:{location}: {error.message}", file=sys.stderr)
            errors += 1

        if record.get("name") != name:
            print(
                f"{path.relative_to(ROOT)}: name '{record.get('name')}' does not match index entry '{name}'",
                file=sys.stderr,
            )
            errors += 1

        upstream = record.get("upstream", {})
        per_postgresql = upstream.get("perPostgresql")
        if isinstance(per_postgresql, dict):
            available_majors = {
                str(major)
                for major, info in record.get("postgresql", {}).items()
                if isinstance(info, dict) and info.get("available") is True
            }
            missing_upstream = sorted(available_majors - set(per_postgresql))
            for major in missing_upstream:
                print(
                    f"{path.relative_to(ROOT)}: upstream.perPostgresql is missing available PostgreSQL major {major}",
                    file=sys.stderr,
                )
                errors += 1

    if EXTENSIONS_DIR.exists():
        unindexed = sorted(
            path.stem
            for path in EXTENSIONS_DIR.glob("*.json")
            if path.stem not in names
        )
        for name in unindexed:
            print(f"extensions/{name}.json exists but is not listed in index.json", file=sys.stderr)
            errors += 1

    if errors:
        print(f"Catalog validation failed with {errors} error(s).", file=sys.stderr)
        return 1

    print(f"Catalog validation passed for {len(names)} extension record(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
