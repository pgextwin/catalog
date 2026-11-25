#!/usr/bin/env python3
"""Static bilingual Pages generator for pgextwin/catalog (Proposal C Phase C1)."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import html
import json
import math
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import package_ledger  # noqa: E402

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
EXT_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ENGLISH_MONTHS = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha256(text: str) -> str:
    data = text.encode("utf-8")
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha256(header + data).hexdigest()


def read_json(path: Path) -> dict | list:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Missing or non-regular JSON file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: object, *, compact: bool = False) -> bytes:
    if compact:
        text = json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    else:
        text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    raw = text.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


def safe_https_url(url: str | None) -> str | None:
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return None
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    return url


def github_repo_url(repo: str | None) -> str | None:
    if isinstance(repo, str) and REPO_RE.fullmatch(repo):
        return f"https://github.com/{repo}"
    return None


def capability_source_url(source: dict | None) -> str | None:
    if not isinstance(source, dict):
        return None
    commit = source.get("commit", "")
    path = source.get("path", "")
    repo_url = github_repo_url(source.get("repository"))
    if not repo_url or not COMMIT_RE.fullmatch(str(commit)):
        return None
    if not isinstance(path, str) or ".." in path or path.startswith("/"):
        return None
    encoded = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
    return f"{repo_url}/blob/{commit}/{encoded}"


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def is_valid_calendar_date(value: str | None) -> bool:
    if not isinstance(value, str) or not DATE_RE.fullmatch(value):
        return False
    try:
        dt.date.fromisoformat(value)
        return True
    except ValueError:
        return False


def format_calendar_date(value: str, lang: str) -> str:
    d = dt.date.fromisoformat(value)
    if lang == "ja":
        return f"{d.year}年{d.month}月{d.day}日"
    return f"{ENGLISH_MONTHS[d.month - 1]} {d.day}, {d.year}"


def next_calendar_date(value: str) -> str:
    return (dt.date.fromisoformat(value) + dt.timedelta(days=1)).isoformat()


def format_major_ranges(majors: list[int]) -> str:
    clean = sorted({m for m in majors if isinstance(m, int)})
    if not clean:
        return ""
    ranges: list[str] = []
    start = prev = clean[0]
    for cur in clean[1:]:
        if cur == prev + 1:
            prev = cur
            continue
        ranges.append(str(start) if start == prev else f"{start}–{prev}")
        start = prev = cur
    ranges.append(str(start) if start == prev else f"{start}–{prev}")
    return ", ".join(ranges)


def has_cjk(text: str) -> bool:
    return bool(re.search(r"[\u3040-\u30ff\u3400-\u9fff]", text))


def split_bilingual(value: str, lang: str) -> str | None:
    if " / " not in value or not has_cjk(value):
        return None
    parts = []
    for part in value.split(" — "):
        at = part.rfind(" / ")
        if at < 0:
            parts.append(part)
            continue
        tail = part[at + 3:]
        if not has_cjk(tail):
            parts.append(part)
        else:
            parts.append(tail if lang == "ja" else part[:at])
    return " — ".join(parts)


def render_localized_text(
    source_en: str,
    lang: str,
    ui: dict,
    *,
    stable_ja: str | None = None,
    explicit_ja: str | None = None,
    pending_badge: bool = True,
) -> tuple[str, str]:
    """Return (html_fragment, plain_text_for_search) according to stable-key translation rules."""
    bilingual = split_bilingual(source_en, lang)
    if bilingual is not None:
        return esc(bilingual), bilingual
    if lang == "en":
        return esc(source_en), source_en
    if explicit_ja:
        return esc(explicit_ja), explicit_ja
    if stable_ja:
        return esc(stable_ja), stable_ja
    if pending_badge:
        badge = esc(ui["translationPending"])
        frag = f'<span lang="en">{esc(source_en)}</span> <span class="translation-pending-badge">{badge}</span>'
        return frag, source_en
    return esc(source_en), source_en


def format_template(template: str, **kwargs: object) -> str:
    result = template
    for k, v in kwargs.items():
        result = result.replace("{" + k + "}", str(v))
    return result


def fetch_github_json(url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "pgextwin-catalog-pages-builder",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def resolve_repo_root(inputs_path: Path) -> Path:
    for parent in [inputs_path.resolve().parent, *inputs_path.resolve().parents]:
        if (parent / "index.json").is_file() and (parent / "packages").is_dir():
            return parent
    return Path.cwd().resolve()


def git_head_commit(repo_root: Path) -> str | None:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_root, stderr=subprocess.DEVNULL)
        sha = out.decode("utf-8").strip()
        return sha if COMMIT_RE.fullmatch(sha) else None
    except Exception:
        return None


def load_postgresql_lifecycle(repo_root: Path, pin: dict, fetch_live: bool) -> tuple[dict, str]:
    if fetch_live:
        repo = pin["repository"]
        path = pin["path"]
        commit = pin["commit"]
        if not REPO_RE.fullmatch(repo) or not COMMIT_RE.fullmatch(commit):
            raise ValueError("Invalid postgresql lifecycle pin")
        raw_url = f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"
        with urllib.request.urlopen(urllib.request.Request(raw_url, headers={"User-Agent": "pgextwin-pages"}), timeout=20) as r:
            raw_bytes = r.read()
    else:
        snap = repo_root / pin["snapshotPath"]
        if snap.is_symlink() or not snap.is_file():
            raise ValueError(f"Missing postgresql snapshot: {snap}")
        raw_bytes = snap.read_bytes()
    actual_sha = sha256_hex(raw_bytes)
    expected_sha = pin.get("snapshotSha256")
    if expected_sha and actual_sha != expected_sha:
        raise ValueError(f"postgresql.json SHA-256 mismatch: expected {expected_sha}, got {actual_sha}")
    data = json.loads(raw_bytes.decode("utf-8"))
    if data.get("schemaVersion") != 1 or not isinstance(data.get("postgresql"), list):
        raise ValueError("Unsupported postgresql.json schema")
    by_major: dict[str, dict] = {}
    for entry in data["postgresql"]:
        major = entry.get("major")
        eol = entry.get("eol")
        if not isinstance(major, int) or not is_valid_calendar_date(eol):
            raise ValueError(f"Invalid postgresql lifecycle entry: {entry}")
        by_major[str(major)] = entry
    return by_major, actual_sha


def load_cli_release_metadata(repo_root: Path, cli_cfg: dict, fetch_live: bool) -> dict:
    repo = cli_cfg["repository"]
    tag = cli_cfg["tag"]
    if not REPO_RE.fullmatch(repo):
        raise ValueError("Invalid CLI repository")
    if fetch_live:
        release = fetch_github_json(f"https://api.github.com/repos/{repo}/releases/tags/{urllib.parse.quote(tag, safe='')}")
        tag_ref = fetch_github_json(f"https://api.github.com/repos/{repo}/git/ref/tags/{urllib.parse.quote(tag, safe='')}")
        obj = tag_ref["object"]
        tag_commit = obj["sha"]
        if obj["type"] == "tag":
            tag_commit = fetch_github_json(f"https://api.github.com/repos/{repo}/git/tags/{tag_commit}")["object"]["sha"]
        snapshot_sha = None
    else:
        snap = repo_root / cli_cfg["snapshotPath"]
        if snap.is_symlink() or not snap.is_file():
            raise ValueError(f"Missing CLI release snapshot: {snap}")
        snap_bytes = snap.read_bytes()
        snapshot_sha = sha256_hex(snap_bytes)
        expected_snap_sha = cli_cfg.get("snapshotSha256")
        if expected_snap_sha and snapshot_sha != expected_snap_sha:
            raise ValueError(f"CLI snapshot SHA-256 mismatch: expected {expected_snap_sha}, got {snapshot_sha}")
        release = json.loads(snap_bytes.decode("utf-8"))
        tag_commit = release.get("tagCommit") or release.get("target_commitish")

    if release.get("id") != cli_cfg["expectedReleaseId"]:
        raise ValueError(f"CLI release ID mismatch: {release.get('id')} != {cli_cfg['expectedReleaseId']}")
    if release.get("tag_name") != tag or release.get("draft") is not False:
        raise ValueError("CLI release tag mismatch or draft release")
    if tag_commit != cli_cfg["expectedTagCommit"]:
        raise ValueError(f"CLI tag commit mismatch: {tag_commit} != {cli_cfg['expectedTagCommit']}")

    assets_by_name = {a["name"]: a for a in release.get("assets", [])}
    exe_asset = assets_by_name.get("pgextwin.exe")
    sums_asset = assets_by_name.get("SHA256SUMS.txt")
    if not exe_asset or not sums_asset:
        raise ValueError("CLI release missing pgextwin.exe or SHA256SUMS.txt")

    def parse_digest(asset: dict) -> str:
        digest = str(asset.get("digest", ""))
        if not digest.startswith("sha256:") or not SHA256_RE.fullmatch(digest[7:]):
            raise ValueError(f"Invalid asset digest on {asset.get('name')}: {digest}")
        return digest[7:]

    exe_url = f"https://github.com/{repo}/releases/download/{tag}/pgextwin.exe"
    sums_url = f"https://github.com/{repo}/releases/download/{tag}/SHA256SUMS.txt"
    release_url = f"https://github.com/{repo}/releases/tag/{tag}"
    if exe_asset.get("browser_download_url") != exe_url or sums_asset.get("browser_download_url") != sums_url:
        raise ValueError("CLI asset URLs are not canonical")
    if release.get("html_url") != release_url:
        raise ValueError("CLI release URL is not canonical")

    exe_bytes = int(exe_asset["size"])
    exe_sha = parse_digest(exe_asset)
    sums_sha = parse_digest(sums_asset)
    version = tag.removeprefix("cli-v")
    published_at = release["published_at"]
    published_date = published_at[:10]
    if not is_valid_calendar_date(published_date):
        raise ValueError(f"Invalid CLI published_at: {published_at}")

    exe_size_mb = f"{math.floor(exe_bytes / 10_000) / 100:.2f} MB"
    return {
        "schemaVersion": 1,
        "repository": repo,
        "tag": tag,
        "version": version,
        "releaseId": release["id"],
        "tagCommit": tag_commit,
        "targetCommitish": release.get("target_commitish"),
        "publishedAt": published_at,
        "publishedDateUtc": published_date,
        "prerelease": bool(release.get("prerelease")),
        "draft": bool(release.get("draft")),
        "releaseUrl": release_url,
        "assets": {
            "exe": {
                "id": exe_asset["id"],
                "name": exe_asset["name"],
                "sizeBytes": exe_bytes,
                "sizeDisplayMb": exe_size_mb,
                "sha256": exe_sha,
                "downloadUrl": exe_url,
            },
            "checksums": {
                "id": sums_asset["id"],
                "name": sums_asset["name"],
                "sizeBytes": int(sums_asset["size"]),
                "sha256": sums_sha,
                "downloadUrl": sums_url,
            },
        },
        "source": {
            "configPath": "site/cli-release.json",
            "snapshotPath": cli_cfg.get("snapshotPath"),
            "snapshotSha256": snapshot_sha,
            "mode": "live-github-api" if fetch_live else "pinned-snapshot",
        },
    }


def project_landscape_v1(identity: dict) -> dict:
    """Reconstruct the legacy v1 landscape record shape from an identity."""
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


def project_distribution_from_identity(
    name: str,
    identity: dict,
    ledger_projected: dict,
    packages_dir: str,
) -> dict:
    """Verify identity metadata and merge its distribution fields onto the ledger projection."""
    if identity.get("schemaVersion") != 1 or identity.get("name") != name:
        raise ValueError(f"Invalid identity header for {name}")
    intake = identity.get("intake")
    if (
        not isinstance(intake, dict)
        or intake.get("class") != "distributed"
        or intake.get("distributionAllowed") is not True
        or intake.get("expectedUpstreamRepository") != identity.get("upstreamRepository")
    ):
        raise ValueError(f"Identity {name} is not an authorized distributed entry")
    dist = identity.get("distribution")
    if not isinstance(dist, dict):
        raise ValueError(f"Missing distribution metadata on identity {name}")
    if dist.get("ledgerPath") != f"{packages_dir}/{name}.json":
        raise ValueError(f"Identity ledgerPath mismatch for {name}")

    derived = copy.deepcopy(ledger_projected)
    derived["name"] = name
    derived["displayName"] = identity.get("displayName", name)
    derived["description"] = identity["description"]
    derived["upstream"]["repository"] = identity["upstreamRepository"]
    derived["repository"] = dist["repository"]
    derived["license"] = dist["license"]
    if "externalSourceRegistry" in dist:
        derived["externalSourceRegistry"] = dist["externalSourceRegistry"]
    else:
        derived.pop("externalSourceRegistry", None)
    return derived


def load_distributed_records(repo_root: Path, catalog_paths: dict) -> list[dict]:
    index = read_json(repo_root / catalog_paths["index"])
    if index.get("schemaVersion") != 2 or not isinstance(index.get("extensions"), list):
        raise ValueError("Invalid catalog index.json")
    names = index["extensions"]
    if names != sorted(set(names)) or not all(EXT_NAME_RE.fullmatch(n) for n in names):
        raise ValueError("Catalog index extensions must be unique, sorted, and valid")

    identities_index = read_json(repo_root / catalog_paths["identitiesIndex"])
    if (
        type(identities_index) is not dict
        or identities_index.get("schemaVersion") != 3
        or identities_index.get("extensions") != names
    ):
        raise ValueError("Invalid or mismatched identities index")

    records: list[dict] = []
    pkg_dir = repo_root / catalog_paths["packagesDir"]
    id_dir = repo_root / catalog_paths["identitiesDir"]
    for name in names:
        ledger = package_ledger.read_record(pkg_dir / f"{name}.json")
        if ledger.get("name") != name or ledger.get("repository") != f"pgextwin/{name}":
            raise ValueError(f"Package ledger identity mismatch for {name}")
        projected = package_ledger.website_record(ledger)
        identity = read_json(id_dir / f"{name}.json")
        identity_derived = project_distribution_from_identity(
            name,
            identity,
            projected,
            catalog_paths["packagesDir"],
        )
        if identity_derived != projected:
            raise ValueError(f"Ledger projection differs from identities/{name}.json")
        records.append(projected)
    records.sort(key=lambda r: r["displayName"].lower())
    # Match JS localeCompare-like case-insensitive / standard sort stability on displayName
    records.sort(key=lambda r: (r["displayName"].casefold(), r["displayName"]))
    return records


def load_landscape_registry(repo_root: Path, catalog_paths: dict) -> list[dict]:
    identities_index = read_json(repo_root / catalog_paths["identitiesIndex"])
    if (
        type(identities_index) is not dict
        or identities_index.get("schemaVersion") != 3
        or not isinstance(identities_index.get("identities"), list)
        or not isinstance(identities_index.get("extensions"), list)
    ):
        raise ValueError("Invalid identities candidate index")

    entries = identities_index["identities"]
    dist_names = identities_index["extensions"]
    if not all(isinstance(n, str) and EXT_NAME_RE.fullmatch(n) for n in dist_names) or len(set(dist_names)) != len(dist_names):
        raise ValueError("Invalid distributed roster in identities index")
    if not all(isinstance(e, dict) and isinstance(e.get("name"), str) and EXT_NAME_RE.fullmatch(e["name"]) for e in entries):
        raise ValueError("Invalid identity entries in identities index")
    names = [e["name"] for e in entries]
    if len(set(names)) != len(names):
        raise ValueError("Duplicate identity names in identities index")

    dist_roster = set(dist_names)
    if {e["name"] for e in entries if e.get("intakeClass") == "distributed"} != dist_roster:
        raise ValueError("Identities index distributed roster mismatch")

    id_dir = repo_root / catalog_paths["identitiesDir"]
    records: list[dict] = []
    for entry in entries:
        name = entry["name"]
        expected_rel = f"{catalog_paths['identitiesDir']}/{name}.json"
        if entry.get("path") != expected_rel:
            raise ValueError(f"Identity path mismatch for {name}: {entry.get('path')!r}")
        identity = read_json(id_dir / f"{name}.json")
        if (
            type(identity) is not dict
            or identity.get("schemaVersion") != 1
            or identity.get("name") != name
            or not isinstance(identity.get("intake"), dict)
            or not isinstance(identity.get("research"), dict)
        ):
            raise ValueError(f"Invalid identity record for {name}")
        intake = identity["intake"]
        intake_class = intake.get("class")
        if (
            intake_class not in ("distributed", "research-only")
            or intake_class != entry.get("intakeClass")
            or (intake_class == "distributed") != (name in dist_roster)
            or intake.get("distributionAllowed") is not (intake_class == "distributed")
        ):
            raise ValueError(f"Identity intake mismatch for {name}")
        if intake_class == "research-only" and "status" not in identity["research"]:
            raise ValueError(f"Research-only identity missing status on {name}")

        rec = project_landscape_v1(identity)
        if rec.get("schemaVersion") != 1 or rec.get("name") != name:
            raise ValueError(f"Invalid landscape record for {name}")
        if rec.get("status") not in ("implemented", "candidate", "not-planned"):
            raise ValueError(f"Invalid landscape status on {name}: {rec.get('status')}")
        if not is_valid_calendar_date(rec.get("lastReviewed")):
            raise ValueError(f"Invalid lastReviewed on {name}")
        if rec.get("status") == "implemented" and rec.get("pgextwinCatalogName") != name:
            raise ValueError(f"Implemented landscape entry mismatch on {name}")
        for url in rec.get("evidenceUrls", []):
            if not safe_https_url(url):
                raise ValueError(f"Unsafe evidence URL on {name}: {url}")
        for src in rec.get("windowsBinarySources", []):
            if not safe_https_url(src.get("url")):
                raise ValueError(f"Unsafe source URL on {name}: {src.get('url')}")
        records.append(rec)
    return records


def sort_landscape_records(records: list[dict]) -> list[dict]:
    alphabetical = sorted(records, key=lambda r: (r["displayName"].casefold(), r["displayName"]))
    order_map = {"wave-2": 0, "reserve": 1, "research": 2}

    def cand_key(r: dict) -> tuple[int, int, str, str]:
        rm = r.get("roadmap") or {}
        dec = rm.get("decision")
        k = order_map.get(dec, 3)
        ord_val = rm.get("order", 0) if k == 0 else 0
        return (k, ord_val, r["displayName"].casefold(), r["displayName"])

    candidates = sorted([r for r in alphabetical if r.get("status") == "candidate"], key=cand_key)
    idx = 0
    result = []
    for r in alphabetical:
        if r.get("status") == "candidate":
            result.append(candidates[idx])
            idx += 1
        else:
            result.append(r)
    return result


def build_landscape_browse_records(
    landscape_records: list[dict],
    direct_records: list[dict],
    standalone_records: list[dict],
    decisions_cfg: dict,
) -> list[dict]:
    by_name: dict[str, dict] = {r["name"]: dict(r) for r in landscape_records}
    decisions = decisions_cfg["decisions"]
    package_details = decisions_cfg["packageDetails"]
    bundle_aliases = {b["sourceItem"]: b for b in decisions_cfg.get("bundleAliases", [])}
    suppressed_sources = set(decisions_cfg.get("suppressWindowsBinarySources", []))

    for name, dec in decisions.items():
        if "displayName" in dec and name not in by_name:
            dn = dec["displayName"]
            en_dn = dn["en"] if isinstance(dn, dict) else dn
            bilingual_dn = f"{dn['en']} / {dn['ja']}" if isinstance(dn, dict) else dn
            by_name[name] = {
                "name": name,
                "displayName": bilingual_dn,
                "displayNameLocalized": dn,
                "windowsBinarySources": [],
            }
            if en_dn and not isinstance(dn, dict):
                by_name[name]["displayName"] = en_dn

    def ensure_pkg_record(name: str) -> dict:
        if name not in by_name:
            detail = package_details.get(name, {})
            dn = detail.get("displayName", name)
            desc = detail.get("description")
            rec: dict = {"name": name, "displayName": dn, "windowsBinarySources": []}
            if desc:
                rec["descriptionLocalized"] = desc
                rec["description"] = f"{desc['en']} / {desc['ja']}"
            by_name[name] = rec
        return by_name[name]

    def add_pkg(name: str, route: str, pkg: dict) -> None:
        rec = ensure_pkg_record(name)
        pkgs = rec.setdefault("packages", {})
        pkgs.setdefault(route, []).append(pkg)

    for route, pkg_list in (("external-direct", direct_records), ("external-standalone", standalone_records)):
        for pkg in pkg_list:
            item_name = pkg.get("extension") or pkg.get("item")
            add_pkg(item_name, route, pkg)
            if item_name in bundle_aliases:
                add_pkg(bundle_aliases[item_name]["bundledItem"], route, pkg)

    for name, rec in by_name.items():
        dec = decisions.get(name)
        if dec and "reason" in dec:
            rec["reasonLocalized"] = dec["reason"]
        distributions: list[str] = []
        if rec.get("status") == "implemented":
            distributions.append("implemented")
        distributions.extend(rec.get("packages", {}).keys())

        if dec and dec.get("clearPackagesAndEvidence"):
            rec["distributions"] = [dec["type"]]
            rec.pop("packages", None)
            rec["evidenceUrls"] = []
            rec["windowsBinarySources"] = []
        else:
            if not distributions:
                fallback = (dec.get("type") if dec else None) or rec.get("status")
                if fallback:
                    distributions = [fallback]
            rec["distributions"] = distributions
            if name in suppressed_sources:
                rec["windowsBinarySources"] = []

    return sort_landscape_records(list(by_name.values()))


def render_distribution_card(
    record: dict,
    lang: str,
    ui: dict,
    descriptions_i18n: dict,
    scenarios_i18n: dict,
    pg_lifecycle: dict[str, dict],
    effective_date: str,
) -> tuple[str, str]:
    u = ui[lang]
    name = record["name"]
    display_name = record["displayName"]
    upstream_repo = record["upstream"]["repository"]
    desc_entry = descriptions_i18n.get(f"{name}.distribution")
    stable_desc_ja = (
        desc_entry["ja"]
        if desc_entry and desc_entry.get("sourceEn") == record["description"]
        else None
    )
    desc_html, desc_plain = render_localized_text(
        record["description"], lang, u, stable_ja=stable_desc_ja, pending_badge=True
    )

    majors_desc = [
        int(m) for m, info in record["postgresql"].items() if info.get("available") is True
    ]
    majors_desc.sort(reverse=True)
    majors_asc = sorted(majors_desc)

    # Summary badges
    summary_badges = [f'<span class="summary-release">{esc(record["latest"]["releaseTag"])}</span>']
    for m in majors_desc:
        summary_badges.append(f'<span class="summary-pg" data-pg="{m}">PG {m}</span>')

    # Binary table rows (descending)
    table_rows: list[str] = []
    for m in majors_desc:
        info = record["postgresql"][str(m)]
        dl_url = safe_https_url(info.get("downloadUrl"))
        zip_cell = (
            f'<a class="download-link download-link--compact" href="{esc(dl_url)}">{esc(u["downloadZip"])}</a>'
            if dl_url
            else f'<span class="link-unavailable">{esc(u["directDownloadUnavailable"])}</span>'
        )
        zip_cell += f'<code class="asset-name">{esc(info["asset"])}</code>'

        ev = info.get("evidence", {})
        supp_links: list[str] = []
        sbom_url = safe_https_url(ev.get("sbom", {}).get("downloadUrl")) if ev.get("sbom", {}).get("available") else None
        vuln_url = safe_https_url(ev.get("vulnerabilityReport", {}).get("downloadUrl")) if ev.get("vulnerabilityReport", {}).get("available") else None
        if sbom_url:
            supp_links.append(f'<a class="inline-link" href="{esc(sbom_url)}">{esc(u["spdxSbomLink"])}</a>')
        if vuln_url:
            supp_links.append(f'<a class="inline-link" href="{esc(vuln_url)}">{esc(u["grypeReportLink"])}</a>')
        supp_inner = "".join(supp_links) if supp_links else esc(u["notPublishedForRelease"])
        table_rows.append(
            f'<tr data-pg="{m}"><th scope="row">PG {m}</th><td>{zip_cell}</td>'
            f'<td><div class="supporting-links">{supp_inner}</div></td></tr>'
        )

    # Overview dl.meta
    up = record["upstream"]
    if up.get("version"):
        up_ver_label = up["version"]
    elif up.get("perPostgresql"):
        up_ver_label = u["perPostgresqlMajor"]
    else:
        up_ver_label = u["unknown"]
    pub_raw = record["latest"]["publishedAt"]
    pub_date = pub_raw[:10] if isinstance(pub_raw, str) and len(pub_raw) >= 10 else u["unknown"]
    meta_pairs = [
        (u["upstreamVersion"], up_ver_label),
        (u["pgextwinRelease"], record["latest"]["releaseTag"]),
        (u["releaseDate"], f"{pub_date} UTC"),
        (u["architecture"], f'Windows {record["architecture"]}'),
        (u["license"], record["license"]),
    ]
    meta_html = "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in meta_pairs)

    # Runtime section
    req = record["runtime"]["requirements"]
    ce = req["clientExecutable"]
    ce_paths = [p for p in ce.get("packagePaths", []) if isinstance(p, str) and p.strip()]
    if ce.get("required") is True:
        ce_label = u["clientExeRequired"] + (f' — {", ".join(ce_paths)}' if ce_paths else "")
    else:
        ce_label = u["clientExeNotRequired"]
    runtime_items = [
        u["extensionCreationLabels"].get(req["extensionCreation"], u["extensionCreationLabels"]["unknown"]),
        u["preloadLabels"].get(req["preload"], u["preloadLabels"]["unknown"]),
        u["bgwUsed"] if req.get("backgroundWorker") is True else u["bgwNotUsed"],
        ce_label,
    ]
    runtime_html = (
        f'<section class="runtime-section"><h4>{esc(u["runtime"])}</h4>'
        f'<ul class="runtime-list">{"".join(f"<li class=\"runtime-item\">{esc(x)}</li>" for x in runtime_items)}</ul>'
        f"</section>"
    )

    # PostgreSQL binaries list (ascending)
    pg_items: list[str] = []
    for m in majors_asc:
        info = record["postgresql"][str(m)]
        lc = pg_lifecycle.get(str(m))
        eol = lc["eol"] if lc else ""
        if is_valid_calendar_date(eol):
            status = "maintained" if effective_date <= eol else "historical"
        else:
            status = "unknown"
        if status == "maintained":
            badge_text = u["maintained"]
            detail_text = format_template(u["binaryDetailMaintained"], eol=eol)
        elif status == "historical":
            badge_text = u["eolHistorical"]
            detail_text = format_template(u["binaryDetailHistorical"], major=m, eol=eol)
        else:
            badge_text = u["lifecycleUnknown"]
            detail_text = u["binaryDetailUnknown"]

        per_pg_ver = (up.get("perPostgresql") or {}).get(str(m), {}).get("version")
        up_major_html = (
            f'<p class="pg-version-upstream">{esc(format_template(u["upstreamVersionForMajor"], major=m, version=per_pg_ver))}</p>'
            if per_pg_ver
            else ""
        )
        dl_url = safe_https_url(info.get("downloadUrl"))
        dl_row = (
            f'<a class="download-link" href="{esc(dl_url)}">{esc(u["downloadZip"])}</a>'
            if dl_url
            else f'<span class="link-unavailable">{esc(u["directDownloadUnavailable"])}</span>'
        )
        copy_aria = format_template(u["copySha256Aria"], displayName=display_name, major=m)
        checksum_html = (
            f'<div class="checksum-block">'
            f'<span class="checksum-label">{esc(u["zipSha256"])}</span>'
            f'<code class="checksum">{esc(info["sha256"])}</code>'
            f'<button class="copy-button" type="button" aria-label="{esc(copy_aria)}" data-sha256="{esc(info["sha256"])}">{esc(u["copySha256"])}</button>'
            f"</div>"
        )

        ev = info.get("evidence", {})
        bpa = ev.get("buildProvenanceAttestation", {}).get("available") is True
        sbom_ok = ev.get("sbom", {}).get("available") is True and safe_https_url(ev.get("sbom", {}).get("downloadUrl"))
        sa_ok = ev.get("sbomAttestation", {}).get("available") is True
        vuln_ok = ev.get("vulnerabilityReport", {}).get("available") is True and safe_https_url(ev.get("vulnerabilityReport", {}).get("downloadUrl"))
        if not (bpa or sbom_ok or sa_ok or vuln_ok):
            ev_body = f'<p class="evidence-note">{esc(u["historicalEvidenceNote"])}</p>'
        else:
            bpa_state = u["available"] if bpa else u["notPublishedForRelease"]
            sa_state = u["available"] if sa_ok else u["notPublishedForRelease"]
            ev_lis = [
                f'<li>{esc(format_template(u["buildProvenanceLabel"], state=bpa_state))}</li>',
                (
                    f'<li>{esc(u["spdxSbomPrefix"])}<a class="inline-link" href="{esc(sbom_ok)}">{esc(u["downloadSpdxJson"])}</a></li>'
                    if sbom_ok
                    else f'<li>{esc(u["spdxSbomUnavailable"])}</li>'
                ),
                f'<li>{esc(format_template(u["sbomAttestationLabel"], state=sa_state))}</li>',
                (
                    f'<li>{esc(u["vulnerabilityReportPrefix"])}<a class="inline-link" href="{esc(vuln_ok)}">{esc(u["downloadGrypeReport"])}</a></li>'
                    if vuln_ok
                    else f'<li>{esc(u["vulnerabilityReportUnavailable"])}</li>'
                ),
            ]
            ev_body = f'<ul class="evidence-list">{"".join(ev_lis)}</ul>'

        pg_items.append(
            f'<li data-pg="{m}"><details class="pg-version" data-pg="{m}" data-eol="{esc(eol)}">'
            f'<summary class="pg-version-summary">'
            f'<span class="pg-version-title"><strong>PostgreSQL {m}</strong></span>'
            f'<span class="lifecycle-badge lifecycle-badge--{status}">{esc(badge_text)}</span>'
            f'</summary>'
            f'<div class="pg-version-body">'
            f'<p class="pg-version-detail">{esc(detail_text)}</p>'
            f'{up_major_html}'
            f'<div class="download-row">{dl_row}</div>'
            f'{checksum_html}'
            f'<section class="evidence"><h5>{esc(u["supplyChainEvidence"])}</h5>{ev_body}</section>'
            f'</div></details></li>'
        )

    # Capabilities / Test Contract
    cap = record["capabilities"]
    scenario_items: list[str] = []
    for sc in cap["functionalScenarios"]:
        sc_id = sc["id"]
        sc_src = sc["description"]
        blob_hash = git_blob_sha256(sc_src)
        stable_key = f"{name}:{sc_id}:{blob_hash}"
        sc_entry = scenarios_i18n.get(stable_key)
        sc_ja = sc_entry["ja"] if sc_entry and sc_entry.get("sourceEn") == sc_src else None
        sc_html, _ = render_localized_text(sc_src, lang, u, stable_ja=sc_ja, pending_badge=True)

        pg_majors = sc.get("postgresqlMajors") or []
        majors_attr = ",".join(str(x) for x in pg_majors)
        scope_html = ""
        if pg_majors:
            ranges = format_major_ranges(pg_majors)
            scope_text = format_template(u["scenarioScopeTemplate"], ranges=ranges)
            scope_html = f'<span class="scope-badge">{esc(scope_text)}</span>'
        scenario_items.append(
            f'<li class="scenario-item" data-pg-majors="{esc(majors_attr)}">'
            f'<span>{sc_html}</span>{scope_html}<code class="scenario-id">{esc(sc_id)}</code></li>'
        )
    scenario_items.append(f'<li class="scenario-item scenario-empty" hidden>{esc(u["noScenarioForMajor"])}</li>')

    cov = cap["coverage"]
    cov_rows = []
    for cov_key, cov_label in u["coverageFields"].items():
        cov_status = cov.get(cov_key, "unknown")
        cov_text = u["coverageStatuses"].get(cov_status, u["coverageStatuses"]["unknown"])
        cov_rows.append(
            f'<dt>{esc(cov_label)}</dt>'
            f'<dd class="coverage-status coverage-status--{esc(cov_status)}">{esc(cov_text)}</dd>'
        )

    cap_src = record["capabilitiesSource"]
    cap_src_label = f'{cap_src["repository"]}/{cap_src["path"]} @ {cap_src["commit"]}'
    cap_src_href = capability_source_url(cap_src)
    cap_src_link = (
        f'<a class="inline-link" href="{esc(cap_src_href)}">{esc(cap_src_label)}</a>'
        if cap_src_href
        else esc(cap_src_label)
    )

    capabilities_html = (
        f'<details class="capabilities"><summary>{esc(u["ciVerifiesSummary"])}</summary>'
        f'<div class="capabilities-body">'
        f'<h5>{esc(u["testedCapabilities"])}</h5>'
        f'<ul class="scenario-list">{"".join(scenario_items)}</ul>'
        f'<h5>{esc(u["ciCoverage"])}</h5>'
        f'<dl class="coverage-list">{"".join(cov_rows)}</dl>'
        f'<p class="capability-source">{esc(u["capabilitySourcePrefix"])}{cap_src_link}</p>'
        f'</div></details>'
    )

    actions_links: list[str] = []
    rel_url = safe_https_url(record["latest"].get("releaseUrl"))
    repo_url = github_repo_url(record["repository"])
    up_url = github_repo_url(upstream_repo)
    if rel_url:
        actions_links.append(f'<a class="inline-link" href="{esc(rel_url)}">{esc(u["releasePage"])}</a>')
    if repo_url:
        actions_links.append(f'<a class="inline-link" href="{esc(repo_url)}">{esc(u["repository"])}</a>')
    if up_url:
        actions_links.append(f'<a class="inline-link" href="{esc(up_url)}">{esc(u["upstream"])}</a>')
    actions_aria = format_template(u["projectLinksAria"], displayName=display_name)

    card_html = (
        f'<article class="extension-card" data-extension="{esc(name)}">'
        f'<details class="extension-collapse" name="pgextwin-extension" id="extension-{esc(name)}">'
        f'<summary class="extension-summary">'
        f'<span class="extension-identity"><span class="extension-title">{esc(display_name)}</span>'
        f'<span class="extension-description">{desc_html}</span></span>'
        f'<span class="extension-summary-badges">{"".join(summary_badges)}</span>'
        f'<span class="summary-affordance">{esc(u["viewDownloads"])}</span>'
        f'</summary>'
        f'<div class="extension-details-body">'
        f'<section class="binary-section"><h4>{esc(u["originalWindowsBinaries"])}</h4>'
        f'<p class="binary-intro">{esc(u["binaryIntro"])}</p>'
        f'<div class="binary-table-scroll"><table class="binary-table">'
        f'<thead><tr><th scope="col">{esc(u["colPostgresql"])}</th>'
        f'<th scope="col">{esc(u["colOriginalZip"])}</th>'
        f'<th scope="col">{esc(u["colSupportingArtifacts"])}</th></tr></thead>'
        f'<tbody>{"".join(table_rows)}</tbody></table></div>'
        f'<p class="binary-hint">{esc(u["binaryHint"])}</p></section>'
        f'<header class="extension-header"><h3>{esc(display_name)}</h3><p>{desc_html}</p></header>'
        f'<h4 class="visually-hidden">{esc(u["overview"])}</h4>'
        f'<dl class="meta">{meta_html}</dl>'
        f'{runtime_html}'
        f'<h4 class="pg-heading">{esc(u["postgresqlBinaries"])}</h4>'
        f'<ul class="pg-list">{"".join(pg_items)}</ul>'
        f'{capabilities_html}'
        f'<nav class="card-actions" aria-label="{esc(actions_aria)}">{"".join(actions_links)}</nav>'
        f'</div></details></article>'
    )
    search_parts = [name, display_name, record["description"], desc_plain, upstream_repo]
    search_text = "\n".join(dict.fromkeys(p for p in search_parts if p))
    return card_html, search_text


def landscape_roadmap_text(record: dict, u: dict) -> str:
    rm = record.get("roadmap")
    if not rm:
        return u["roadmapLabels"]["pending"]
    dec = rm.get("decision")
    if dec == "wave-2":
        tpl = u["roadmapLabels"]["wave2Implemented"] if record.get("status") == "implemented" else u["roadmapLabels"]["wave2"]
        return format_template(tpl, order=rm["order"])
    if dec == "reserve":
        return u["roadmapLabels"]["reserve"]
    if dec == "research":
        return u["roadmapLabels"]["research"]
    return u["roadmapLabels"]["pending"]


def render_landscape_card(
    record: dict,
    lang: str,
    ui: dict,
    descriptions_i18n: dict,
    landscape_i18n: dict,
    decisions_cfg: dict,
) -> tuple[str, str]:
    u = ui[lang]
    name = record["name"]
    search_terms: list[str] = [name]

    dn_loc = record.get("displayNameLocalized")
    if isinstance(dn_loc, dict):
        display_name = dn_loc[lang]
        search_terms.extend([dn_loc["en"], dn_loc["ja"], record["displayName"]])
    else:
        display_name = record["displayName"]
        search_terms.append(display_name)

    desc_html = ""
    if record.get("descriptionLocalized"):
        dloc = record["descriptionLocalized"]
        desc_text = dloc[lang]
        desc_html = esc(desc_text)
        search_terms.extend([dloc["en"], dloc["ja"]])
    elif record.get("description"):
        src_desc = record["description"]
        desc_entry = descriptions_i18n.get(f"{name}.landscape")
        stable_ja = desc_entry["ja"] if desc_entry and desc_entry.get("sourceEn") == src_desc else None
        desc_html, desc_plain = render_localized_text(
            src_desc, lang, u, stable_ja=stable_ja, pending_badge=True
        )
        search_terms.extend([src_desc, desc_plain])

    distributions = record.get("distributions", [])
    summary_badges = [
        f'<span class="landscape-status-label landscape-status-label--{esc(route)}">{esc(u["distributionLabels"][route])}</span>'
        for route in distributions
    ]
    if not distributions:
        summary_badges.append(f'<span class="landscape-status-label">{esc(u["cliStatusUnavailable"])}</span>')
    roadmap_label_text = landscape_roadmap_text(record, u)
    if record.get("roadmap"):
        summary_badges.append(f'<span class="summary-roadmap">{esc(roadmap_label_text)}</span>')

    detail_parts: list[str] = [f"<h3>{esc(display_name)}</h3>"]
    if desc_html:
        detail_parts.append(f"<p>{desc_html}</p>")

    candidate = "candidate" in distributions
    meta_rows: list[tuple[str, str]] = []
    if record.get("upstreamRepository"):
        meta_rows.append((u["upstream"], record["upstreamRepository"]))
        search_terms.append(record["upstreamRepository"])
    if record.get("lastReviewed"):
        meta_rows.append((u["lastReviewed"], format_template(u["recheckBeforeUse"], date=record["lastReviewed"])))

    if candidate and record.get("status") == "candidate":
        detail_parts.append(f'<p class="landscape-roadmap-label">{esc(roadmap_label_text)}</p>')
        meta_rows.append((u["formalRoadmap"], roadmap_label_text))
        if record.get("roadmap"):
            meta_rows.append((u["decisionDate"], record["roadmap"]["decisionDate"]))
        meta_rows.extend([
            (u["stableVersion"], record["currentStableVersion"]),
            (u["license"], record["license"]),
            (u["windowsBuildEffort"], u["candidateValues"].get(record["estimatedWindowsEffort"], record["estimatedWindowsEffort"])),
            (u["pg18Label"], u["candidateValues"].get(record["pg18Support"], record["pg18Support"])),
            (u["pg19ReadinessLabel"], u["candidateValues"].get(record["pg19Readiness"], record["pg19Readiness"])),
            (u["upstreamWindowsLabel"], u["candidateValues"].get(record["windowsUpstreamSupport"], record["windowsUpstreamSupport"])),
            (u["existingSourceLabel"], u["candidateValues"].get(record["knownWindowsBinaryAvailability"], record["knownWindowsBinaryAvailability"])),
        ])

    if "implemented" in distributions and record.get("roadmap"):
        meta_rows.append((u["historicalRoadmap"], roadmap_label_text))
        meta_rows.append((u["selectionDate"], record["roadmap"]["decisionDate"]))

    if meta_rows:
        detail_parts.append('<dl class="meta">' + "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in meta_rows) + "</dl>")

    if "implemented" in distributions:
        if record.get("roadmap"):
            rm_src = record["roadmap"]["rationale"]
            rm_key = f"{name}.roadmap.rationale:{git_blob_sha256(rm_src)}"
            rm_ja = (landscape_i18n.get(rm_key) or {}).get("ja")
            rm_html, rm_plain = render_localized_text(rm_src, lang, u, stable_ja=rm_ja, pending_badge=True)
            search_terms.extend([rm_src, rm_plain])
            detail_parts.append(f'<p class="landscape-roadmap-label">{esc(roadmap_label_text)}</p>')
            detail_parts.append(f'<p class="landscape-muted">{esc(u["originalSelectionRationale"])}{rm_html}</p>')
        detail_parts.append(f'<p>{esc(u["publishedInCatalogNote"])}</p>')
        cat_target = record.get("pgextwinCatalogName") or name
        detail_parts.append(
            f'<p><a class="download-link" href="#extension-{esc(cat_target)}" data-catalog-target="{esc(cat_target)}">'
            f'{esc(u["findPgextwinDownloads"])}</a></p>'
        )

    if record.get("reasonLocalized"):
        rloc = record["reasonLocalized"]
        reason_text = rloc[lang]
        search_terms.extend([rloc["en"], rloc["ja"]])
        detail_parts.append(f'<h4>{esc(u["distributionDecision"])}</h4><p>{esc(reason_text)}</p>')

    bundle_notes = {b["bundledItem"]: b for b in decisions_cfg.get("bundleAliases", [])}
    for route, packages in (record.get("packages") or {}).items():
        pkg_sec = [f'<h4>{esc(u["distributionLabels"][route])}</h4>']
        if name in bundle_notes:
            pkg_sec.append(f'<p>{esc(bundle_notes[name]["note"][lang])}</p>')
        pkg_lis: list[str] = []
        sorted_pkgs = sorted(packages, key=lambda p: int(p["pgMajor"]) if p.get("pgMajor") else 0)
        for pkg in sorted_pkgs:
            target = f'PostgreSQL {pkg["pgMajor"]}' if pkg.get("pgMajor") else u["independentOfPgMajor"]
            ver_prefix = bundle_notes[name]["versionPrefix"] if name in bundle_notes else ""
            ver_str = f'{ver_prefix}{pkg["upstreamVersion"]}'
            entry_html = f'{esc(ver_str)} · {esc(target)} · <code>{esc(pkg["assetName"])}</code>'
            if pkg.get("pgroutingVersion"):
                entry_html += f' · pgRouting {esc(pkg["pgroutingVersion"])}'
            if pkg.get("sourceRepo"):
                entry_html += f' · {esc(pkg["sourceRepo"])}'
                search_terms.append(pkg["sourceRepo"])
            pkg_lis.append(f"<li>{entry_html}</li>")
        pkg_sec.append(f'<ul class="landscape-packages">{"".join(pkg_lis)}</ul>')
        detail_parts.append(f'<section>{"".join(pkg_sec)}</section>')

    if record.get("packages"):
        detail_parts.append(f'<a class="inline-link" href="./cli.html">{esc(u["seeCliInstructions"])}</a>')

    if candidate and record.get("status") == "candidate":
        if not record.get("reasonLocalized"):
            cand_src = record["candidateRationale"]
            cand_key = f"{name}.candidateRationale:{git_blob_sha256(cand_src)}"
            cand_ja = (landscape_i18n.get(cand_key) or {}).get("ja")
            cand_html, cand_plain = render_localized_text(cand_src, lang, u, stable_ja=cand_ja, pending_badge=True)
            search_terms.extend([cand_src, cand_plain])
            detail_parts.append(f'<h4>{esc(u["whyConsiderIt"])}</h4><p>{cand_html}</p>')
        detail_parts.append(f'<h4>{esc(u["selectionRationale"])}</h4>')
        if record.get("roadmap"):
            rm_src = record["roadmap"]["rationale"]
            rm_key = f"{name}.roadmap.rationale:{git_blob_sha256(rm_src)}"
            rm_ja = (landscape_i18n.get(rm_key) or {}).get("ja")
            rm_html, rm_plain = render_localized_text(rm_src, lang, u, stable_ja=rm_ja, pending_badge=True)
            search_terms.extend([rm_src, rm_plain])
            detail_parts.append(f"<p>{rm_html}</p>")
        else:
            detail_parts.append(f'<p>{esc(u["formalDecisionPending"])}</p>')
        if not record.get("windowsBinarySources"):
            detail_parts.append(f'<p class="landscape-muted">{esc(u["noWindowsBinaryIdentified"])}</p>')

    if "not-planned" in distributions and not record.get("reasonLocalized"):
        np_src = record["notPlannedReason"]
        np_ja_explicit = record.get("notPlannedReasonJa")
        np_key = f"{name}.notPlannedReason:{git_blob_sha256(np_src)}"
        np_ja_stable = (landscape_i18n.get(np_key) or {}).get("ja")
        np_html, np_plain = render_localized_text(
            np_src, lang, u, stable_ja=np_ja_stable, explicit_ja=np_ja_explicit, pending_badge=True
        )
        search_terms.extend([np_src, np_plain])
        detail_parts.append(f'<h4>{esc(u["whyNotPlanned"])}</h4><p>{np_html}</p>')

    sources = record.get("windowsBinarySources") or []
    if sources:
        src_lis: list[str] = []
        for s in sources:
            search_terms.append(s["provider"])
            label_str = " — ".join([
                u["sourceTypes"][s["type"]],
                u["sourceAccess"][s["availability"]],
                u["sourceTarget"][s["postgresqlDistribution"]],
                u["sourceCompatibility"][s["compatibility"]],
            ])
            note_src = s["notes"]
            note_key = f"{name}.source:{git_blob_sha256(note_src)}"
            note_ja = (landscape_i18n.get(note_key) or {}).get("ja")
            note_html, note_plain = render_localized_text(note_src, lang, u, stable_ja=note_ja, pending_badge=True)
            search_terms.extend([note_src, note_plain])
            src_href = safe_https_url(s.get("url"))
            action_html = (
                f'<a class="inline-link" href="{esc(src_href)}" target="_blank" rel="noopener noreferrer">{esc(u["openProviderPage"])}</a>'
                if src_href
                else f'<span>{esc(u["acquisitionUrlUnavailable"])}</span>'
            )
            src_lis.append(
                f'<li class="landscape-source">'
                f'<p class="source-provider">{esc(s["provider"])}</p>'
                f'<p>{esc(label_str)}</p>'
                f'<p>{note_html}</p>'
                f'<p>{action_html}</p></li>'
            )
        detail_parts.append(f'<h4>{esc(u["externalBinarySources"])}</h4><ul class="landscape-sources">{"".join(src_lis)}</ul>')

    ev_urls = [u_str for u_str in (record.get("evidenceUrls") or []) if safe_https_url(u_str)]
    if ev_urls:
        ev_lis = "".join(
            f'<li><a href="{esc(url)}" target="_blank" rel="noopener noreferrer">{esc(format_template(u["sourceItemLabel"], index=i))}</a></li>'
            for i, url in enumerate(ev_urls, 1)
        )
        detail_parts.append(f'<details><summary>{esc(u["researchEvidence"])}</summary><ul>{ev_lis}</ul></details>')

    card_html = (
        f'<article class="extension-card landscape-card" data-landscape="{esc(name)}">'
        f'<details class="landscape-collapse" name="pgextwin-landscape" id="landscape-{esc(name)}">'
        f'<summary class="landscape-summary">'
        f'<span class="extension-identity"><span class="extension-title">{esc(display_name)}</span>'
        + (f'<span class="extension-description">{desc_html}</span>' if desc_html else "")
        + f'</span>'
        f'<span class="extension-summary-badges">{"".join(summary_badges)}</span>'
        f'<span class="summary-affordance">{esc(u["viewDetails"])}</span>'
        f'</summary>'
        f'<div class="landscape-detail-body">{"".join(detail_parts)}</div>'
        f'</details></article>'
    )
    search_text = "\n".join(dict.fromkeys(p for p in search_terms if p))
    return card_html, search_text


def render_cli_included_items(direct_records: list[dict], standalone_records: list[dict], lang: str) -> str:
    items_html: list[str] = []

    # Group direct-get records preserving first-seen extension order
    grouped: dict[str, list[dict]] = {}
    for rec in direct_records:
        grouped.setdefault(rec["extension"], []).append(rec)

    for ext, rows in grouped.items():
        majors = sorted({int(r["pgMajor"]) for r in rows if r.get("pgMajor")})
        range_str = format_major_ranges(majors)
        if ext == "postgis" and any(r.get("pgroutingVersion") for r in rows):
            if lang == "ja":
                items_html.append(f"<li>PostGIS／pgRoutingバンドル：PostgreSQL {esc(range_str.replace('–', '～'))}</li>")
            else:
                items_html.append(f"<li>PostGIS/pgRouting bundles: PostgreSQL {esc(range_str)}</li>")
        else:
            versions = sorted({r["upstreamVersion"] for r in rows})
            ver = versions[0] if len(versions) == 1 else ", ".join(versions)
            if lang == "ja":
                items_html.append(f"<li>{esc(ext)} {esc(ver)}：PostgreSQL {esc(range_str.replace('–', '～'))}</li>")
            else:
                items_html.append(f"<li>{esc(ext)} {esc(ver)}: PostgreSQL {esc(range_str)}</li>")

    for rec in standalone_records:
        cat = rec["category"]
        item = rec["item"]
        ver = rec["upstreamVersion"]
        if cat == "spatial" and item == "postgis":
            pg_ver = rec.get("pgroutingVersion", "")
            major = rec.get("pgMajor", "")
            if lang == "ja":
                items_html.append(
                    f"<li>空間拡張：PostGISバンドル {esc(ver)}（pgRouting {esc(pg_ver)}入り、インストーラー形式）：PostgreSQL {esc(major)}</li>"
                )
            else:
                items_html.append(
                    f"<li>Spatial: PostGIS bundle {esc(ver)} with pgRouting {esc(pg_ver)} (installer): PostgreSQL {esc(major)}</li>"
                )
        elif cat == "tools":
            label = "ツール" if lang == "ja" else "Tools"
            sep = "：" if lang == "ja" else ": "
            disp = "PgBouncer" if item == "pgbouncer" else item
            items_html.append(f"<li>{esc(label)}{sep}{esc(disp)} {esc(ver)}</li>")
        elif cat == "drivers":
            label = "ドライバ" if lang == "ja" else "Drivers"
            sep = "：" if lang == "ja" else ": "
            disp = "psqlODBC" if item == "psqlodbc" else item
            short_ver = ver[:-5] if ver.endswith(".0000") else ver
            items_html.append(f"<li>{esc(label)}{sep}{esc(disp)} {esc(short_ver)}</li>")

    return "".join(items_html)


def render_template(template_text: str, mapping: dict[str, str]) -> str:
    rendered = template_text
    for key, value in mapping.items():
        rendered = rendered.replace("{{" + key + "}}", value)
    leftover = re.findall(r"\{\{[A-Za-z0-9_]+\}\}", rendered)
    if leftover:
        raise ValueError(f"Unreplaced template placeholders: {leftover}")
    return rendered


def render_home_page(
    *,
    lang: str,
    template_text: str,
    site_base_url: str,
    filters_filename: str,
    effective_date: str,
    available_majors: list[int],
    pg_lifecycle: dict[str, dict],
    ui: dict,
    cli_meta: dict,
    cli_content: dict,
    extensions_html: str,
    ext_count: int,
    landscape_grid_html: str,
    landscape_count: int,
) -> str:
    u = ui[lang]
    other_lang = "ja" if lang == "en" else "en"
    lang_nav = (
        f'<a href="../{lang}/" lang="{lang}" aria-current="page">{esc(u["languageName"])}</a>'
        f'<a href="../{other_lang}/" lang="{other_lang}">{esc(u["otherLanguageName"])}</a>'
    )
    quickstart_html = "\n        ".join(f"<li>{step}</li>" for step in u["quickstartSteps"])
    noun = u["extensionSingular"] if ext_count == 1 else u["extensionPlural"]
    catalog_count_text = format_template(u["catalogCountTemplate"], count=ext_count, noun=noun)
    pg_options_html = "\n            ".join(
        f'<option value="{m}">{esc(format_template(u["pgVersionOption"], major=m))}</option>'
        for m in available_majors
    )
    catalog_status_text = format_template(u["catalogStatusTemplate"], count=ext_count, date=effective_date)
    results_count_text = format_template(u["resultsCountTemplate"], shown=ext_count, total=ext_count)

    # CLI teaser
    teaser = cli_content["homeTeaser"][lang]
    release_badge = u["prereleaseBadge"] if cli_meta["prerelease"] else u["stableBadge"]
    version = cli_meta["version"]
    exe_size_mb = cli_meta["assets"]["exe"]["sizeDisplayMb"]
    exe_url = cli_meta["assets"]["exe"]["downloadUrl"]
    teaser_cmds = "".join(
        f'<div><strong>{esc(cmd["title"])}</strong><pre><code>{esc(cmd["command"])}</code></pre></div>'
        for cmd in teaser["commands"]
    )
    cli_home_teaser_html = (
        f'<p class="eyebrow">{esc(format_template(teaser["eyebrow"], version=version, releaseBadge=release_badge))}</p>\n'
        f'      <h2 id="cli-home-heading">{esc(teaser["heading"])}</h2>\n'
        f'      <div class="cli-command-list">\n        {teaser_cmds}\n      </div>\n'
        f'      <p>{teaser["descriptionHtml"]}</p>\n'
        f'      <div class="cli-teaser-actions"><a class="download-link" href="{esc(exe_url)}">'
        f'{esc(format_template(teaser["downloadLabel"], version=version, exeSizeMb=exe_size_mb))}</a>'
        f'<a href="./cli.html">{esc(teaser["guideLabel"])}</a></div>'
    )

    # Landscape filters
    dl_opts = "".join(
        f'<option value="{k}">{esc(u["distributionLabels"][k])}</option>'
        for k in ("implemented", "external-direct", "external-standalone")
    )
    unavail_opts = "".join(
        f'<option value="{k}">{esc(u["distributionLabels"][k])}</option>'
        for k in ("candidate", "license-excluded", "not-planned")
    )
    landscape_filter_groups = (
        f'<optgroup label="{esc(u["landscapeGroupDownloadable"])}">{dl_opts}</optgroup>\n            '
        f'<optgroup label="{esc(u["landscapeGroupUnavailable"])}">{unavail_opts}</optgroup>'
    )
    landscape_source_opts = "\n            ".join(
        f'<option value="{k}">{esc(v)}</option>' for k, v in u["landscapeSourceTypes"].items()
    )
    landscape_status_text = format_template(u["landscapeStatusTemplate"], count=landscape_count)
    landscape_count_text = format_template(u["landscapeCountTemplate"], shown=landscape_count, total=landscape_count)

    # Lifecycle notice for PG14
    pg14 = pg_lifecycle.get("14")
    if pg14 and is_valid_calendar_date(pg14.get("eol")):
        eol14 = pg14["eol"]
        nxt14 = next_calendar_date(eol14)
        eol_fmt = format_calendar_date(eol14, lang)
        nxt_fmt = format_calendar_date(nxt14, lang)
        tpl = u["lifecycleNoticeMaintained"] if effective_date <= eol14 else u["lifecycleNoticeHistorical"]
        notice_text = format_template(tpl, major=14, eolFormatted=eol_fmt, nextFormatted=nxt_fmt)
    else:
        notice_text = u["lifecycleNoticeUnknown"]
    p_attr = ' lang="ja"' if lang == "ja" else ""
    lifecycle_notice_html = f"<p{p_attr}>{esc(notice_text)}</p>"

    return render_template(
        template_text,
        {
            "lang": lang,
            "filtersFilename": filters_filename,
            "effectiveDate": effective_date,
            "metaDescription": esc(u["homeMetaDescription"]),
            "title": esc(u["homeTitle"]),
            "siteBaseUrl": esc(site_base_url),
            "skipToDownloads": esc(u["skipToDownloads"]),
            "navLanguageLabel": esc(u["navLanguageLabel"]),
            "languageNavHtml": lang_nav,
            "heroEyebrow": esc(u["heroEyebrow"]),
            "heroHeading": esc(u["heroHeading"]),
            "heroLead": esc(u["heroLead"]),
            "jumpNavAria": esc(u["jumpNavAria"]),
            "jumpBrowseDownloads": esc(u["jumpBrowseDownloads"]),
            "jumpCliLabel": esc(format_template(u["jumpCliLabel"], version=version)),
            "jumpLandscape": esc(u["jumpLandscape"]),
            "jumpAbout": esc(u["jumpAbout"]),
            "quickstartEyebrow": esc(u["quickstartEyebrow"]),
            "quickstartHeading": esc(u["quickstartHeading"]),
            "quickstartStepsHtml": quickstart_html,
            "catalogEyebrow": esc(u["catalogEyebrow"]),
            "catalogHeading": esc(u["catalogHeading"]),
            "catalogHintTitle": esc(u["catalogHintTitle"]),
            "catalogCountText": esc(catalog_count_text),
            "catalogHintBody": esc(u["catalogHintBody"]),
            "filtersAria": esc(u["filtersAria"]),
            "searchLabel": esc(u["searchLabel"]),
            "searchPlaceholder": esc(u["searchPlaceholder"]),
            "pgFilterLabel": esc(u["pgFilterLabel"]),
            "allPgVersions": esc(u["allPgVersions"]),
            "pgFilterOptionsHtml": pg_options_html,
            "catalogStatusText": esc(catalog_status_text),
            "resultsCountText": esc(results_count_text),
            "catalogEmptyFiltered": esc(u["catalogEmptyFiltered"]),
            "extensionsHtml": extensions_html,
            "cliHomeTeaserHtml": cli_home_teaser_html,
            "landscapeHeading": esc(u["landscapeHeading"]),
            "landscapeIntro": esc(u["landscapeIntro"]),
            "landscapeDisclaimer": esc(u["landscapeDisclaimer"]),
            "landscapeFiltersAria": esc(u["landscapeFiltersAria"]),
            "landscapeSearchLabel": esc(u["landscapeSearchLabel"]),
            "landscapeSearchPlaceholder": esc(u["landscapeSearchPlaceholder"]),
            "landscapeFilterLabel": esc(u["landscapeFilterLabel"]),
            "landscapeFilterAll": esc(u["landscapeFilterAll"]),
            "landscapeFilterGroupsHtml": landscape_filter_groups,
            "landscapeSourceFilterLabel": esc(u["landscapeSourceFilterLabel"]),
            "landscapeSourceAll": esc(u["landscapeSourceAll"]),
            "landscapeSourceOptionsHtml": landscape_source_opts,
            "landscapeStatusText": esc(landscape_status_text),
            "landscapeCountText": esc(landscape_count_text),
            "landscapeEmptyFiltered": esc(u["landscapeEmptyFiltered"]),
            "landscapeGridHtml": landscape_grid_html,
            "lifecycleEyebrow": esc(u["lifecycleEyebrow"]),
            "lifecycleHeading": esc(u["lifecycleHeading"]),
            "lifecycleBodyHtml": u["lifecycleBodyHtml"],
            "lifecycleNoticeHtml": lifecycle_notice_html,
            "integrityEyebrow": esc(u["integrityEyebrow"]),
            "integrityHeading": esc(u["integrityHeading"]),
            "integrityBody": esc(u["integrityBody"]),
            "aboutEyebrow": esc(u["aboutEyebrow"]),
            "aboutHeading": esc(u["aboutHeading"]),
            "aboutBody": esc(u["aboutBody"]),
            "footerGithub": esc(u["footerGithub"]),
            "footerCatalog": esc(u["footerCatalog"]),
            "footerCli": esc(u["footerCli"]),
            "releaseLimitationsTitle": esc(u["releaseLimitationsTitle"]),
            "releaseLimitationsBody": esc(u["releaseLimitationsBody"]),
        },
    )


def render_cli_page(
    *,
    lang: str,
    template_text: str,
    site_base_url: str,
    ui: dict,
    cli_cfg: dict,
    cli_meta: dict,
    cli_content: dict,
    pg_lifecycle: dict[str, dict],
    direct_records: list[dict],
    standalone_records: list[dict],
) -> str:
    u = ui[lang]
    c = cli_content["cliPage"][lang]
    other_lang = "ja" if lang == "en" else "en"
    lang_nav = (
        f'<a href="../{lang}/cli.html" lang="{lang}" aria-current="page">{esc(u["languageName"])}</a>\n      '
        f'<a href="../{other_lang}/cli.html" lang="{other_lang}">{esc(u["otherLanguageName"])}</a>'
    )
    version = cli_meta["version"]
    release_badge = u["prereleaseBadge"] if cli_meta["prerelease"] else u["stableBadge"]
    pub_formatted = format_calendar_date(cli_meta["publishedDateUtc"], lang)
    exe = cli_meta["assets"]["exe"]
    exe_bytes_fmt = f'{exe["sizeBytes"]:,}'
    exe_size_mb = exe["sizeDisplayMb"]
    pg14_eol_fmt = format_calendar_date(pg_lifecycle["14"]["eol"], lang)

    cmd_groups_html = []
    for grp in c["commandGroups"]:
        cmds = "\n".join(esc(line) for line in grp["commands"])
        part = f'<h3>{esc(grp["heading"])}</h3>\n      <pre class="cli-usage"><code>{cmds}</code></pre>'
        if grp.get("noteHtml"):
            part += f'\n      <p>{grp["noteHtml"]}</p>'
        cmd_groups_html.append(part)

    examples_html = "\n        ".join(
        f'<div><h4>{esc(ex["title"])}</h4><pre><code>{esc(ex["command"])}</code></pre></div>'
        for ex in c["examples"]
    )
    included_items_html = render_cli_included_items(direct_records, standalone_records, lang)
    flow_steps_html = "\n        ".join(
        f'<li><h3>{esc(step["title"])}</h3><p>{step["bodyHtml"]}</p></li>'
        for step in c["flowSteps"]
    )
    verify_blocks_html = "\n      ".join(
        f'<p>{blk["descriptionHtml"]}</p>\n      <pre class="cli-usage"><code>{esc(blk["command"])}</code></pre>'
        for blk in c["verifyBlocks"]
    )
    release_notes_tpl = cli_cfg["releaseNotesSummary"][lang]
    release_notes_html = format_template(
        release_notes_tpl,
        version=esc(version),
        publishedDate=esc(pub_formatted),
        exeBytesFormatted=esc(exe_bytes_fmt),
        exeSizeMb=esc(exe_size_mb),
    )

    return render_template(
        template_text,
        {
            "lang": lang,
            "metaDescription": esc(format_template(c["metaDescription"], version=version)),
            "pageTitle": esc(format_template(c["pageTitle"], version=version)),
            "siteBaseUrl": esc(site_base_url),
            "skipLink": esc(c["skipLink"]),
            "navLanguageLabel": esc(u["navLanguageLabel"]),
            "languageNavHtml": lang_nav,
            "eyebrow": esc(c["eyebrow"]),
            "h1": esc(format_template(c["h1"], version=version)),
            "lead": esc(c["lead"]),
            "heroDescriptionHtml": c["heroDescriptionHtml"],
            "navAriaLabel": esc(c["navAriaLabel"]),
            "navDownload": esc(c["nav"]["download"]),
            "navCommands": esc(c["nav"]["commands"]),
            "navChecksum": esc(c["nav"]["checksum"]),
            "navCatalog": esc(c["nav"]["catalog"]),
            "downloadEyebrow": esc(format_template(c["downloadEyebrow"], releaseBadge=release_badge, publishedDate=pub_formatted)),
            "downloadHeading": esc(c["downloadHeading"]),
            "exeUrl": esc(exe["downloadUrl"]),
            "downloadExeLabel": esc(format_template(c["downloadExeLabel"], exeSizeMb=exe_size_mb)),
            "releaseUrl": esc(cli_meta["releaseUrl"]),
            "releaseLinkLabel": esc(format_template(c["releaseLinkLabel"], version=version)),
            "checksumsUrl": esc(cli_meta["assets"]["checksums"]["downloadUrl"]),
            "checksumsLinkLabel": esc(c["checksumsLinkLabel"]),
            "exeSizeLabel": esc(format_template(c["exeSizeLabel"], exeBytesFormatted=exe_bytes_fmt)),
            "exeShaLabel": esc(c["exeShaLabel"]),
            "exeSha256": esc(exe["sha256"]),
            "afterDownloadText": esc(c["afterDownloadText"]),
            "commandsHeading": esc(c["commandsHeading"]),
            "commandsIntroHtml": c["commandsIntroHtml"],
            "commandGroupsHtml": "\n      ".join(cmd_groups_html),
            "examplesHeading": esc(c["examplesHeading"]),
            "examplesHtml": examples_html,
            "includedHeading": esc(c["includedHeading"]),
            "includedItemsHtml": included_items_html,
            "includedFooter": esc(c["includedFooter"]),
            "flowEyebrow": esc(c["flowEyebrow"]),
            "flowHeading": esc(c["flowHeading"]),
            "flowStepsHtml": flow_steps_html,
            "checksumHeading": esc(c["checksumHeading"]),
            "checksumText": esc(c["checksumText"]),
            "verifyHeading": esc(c["verifyHeading"]),
            "verifyBlocksHtml": verify_blocks_html,
            "cautionHeading": esc(c["cautionHeading"]),
            "cautionBody": esc(format_template(c["cautionBody"], pg14EolDate=pg14_eol_fmt)),
            "releaseNotesHeading": esc(c["releaseNotesHeading"]),
            "releaseNotesTitle": esc(format_template(c["releaseNotesTitle"], version=version)),
            "releaseNotesBodyHtml": release_notes_html,
            "backToCatalog": esc(c["backToCatalog"]),
        },
    )


def build_site(
    inputs_path: Path,
    output_dir: Path,
    *,
    effective_date: str | None = None,
    cli_metadata_path: Path | None = None,
    fetch_live: bool = False,
) -> dict:
    repo_root = resolve_repo_root(inputs_path)
    inputs_raw = inputs_path.read_bytes()
    inputs_sha = sha256_hex(inputs_raw)
    inputs_cfg = json.loads(inputs_raw.decode("utf-8"))
    if inputs_cfg.get("schemaVersion") != 1:
        raise ValueError("Unsupported inputs.json schemaVersion")

    eff_date = effective_date or inputs_cfg.get("effectiveDate") or dt.datetime.now(dt.timezone.utc).date().isoformat()
    if not is_valid_calendar_date(eff_date):
        raise ValueError(f"Invalid effectiveDate: {eff_date}")

    site_base_url = inputs_cfg["siteBaseUrl"]
    if not safe_https_url(site_base_url):
        raise ValueError(f"Unsafe siteBaseUrl: {site_base_url}")
    if not site_base_url.endswith("/"):
        site_base_url += "/"

    pg_lifecycle, pg_snap_sha = load_postgresql_lifecycle(repo_root, inputs_cfg["postgresqlLifecycle"], fetch_live)
    cli_cfg = read_json(repo_root / inputs_cfg["cliReleasePath"])
    cli_meta = load_cli_release_metadata(repo_root, cli_cfg, fetch_live)

    dist_records = load_distributed_records(repo_root, inputs_cfg["catalogPaths"])
    landscape_registry = load_landscape_registry(repo_root, inputs_cfg["catalogPaths"])
    direct_records = read_json(repo_root / inputs_cfg["catalogPaths"]["externalDirectGet"])["records"]
    standalone_records = read_json(repo_root / inputs_cfg["catalogPaths"]["externalStandaloneGet"])["records"]

    decisions_cfg = read_json(repo_root / inputs_cfg["landscapeDecisionsPath"])
    cli_content = read_json(repo_root / inputs_cfg["cliContentPath"])

    i18n_dir = repo_root / inputs_cfg["translationsDir"]
    ui = read_json(i18n_dir / "ui.json")
    descriptions_i18n = read_json(i18n_dir / "descriptions.json")
    scenarios_i18n = read_json(i18n_dir / "scenarios.json")
    landscape_i18n = read_json(i18n_dir / "landscape.json")

    browse_records = build_landscape_browse_records(
        landscape_registry, direct_records, standalone_records, decisions_cfg
    )

    available_majors = sorted({
        int(m)
        for rec in dist_records
        for m, info in rec["postgresql"].items()
        if info.get("available") is True
    })

    # Render extension and landscape cards for both languages and construct filter index
    rendered_ext_cards: dict[str, list[str]] = {"en": [], "ja": []}
    ext_filter_entries: list[dict] = []
    for rec in dist_records:
        majors = sorted(int(m) for m, info in rec["postgresql"].items() if info.get("available") is True)
        en_html, en_search = render_distribution_card(
            rec, "en", ui, descriptions_i18n, scenarios_i18n, pg_lifecycle, eff_date
        )
        ja_html, ja_search = render_distribution_card(
            rec, "ja", ui, descriptions_i18n, scenarios_i18n, pg_lifecycle, eff_date
        )
        rendered_ext_cards["en"].append(en_html)
        rendered_ext_cards["ja"].append(ja_html)
        ext_filter_entries.append({
            "name": rec["name"],
            "displayName": rec["displayName"],
            "availableMajors": majors,
            "searchText": {"en": en_search, "ja": ja_search},
        })

    rendered_land_cards: dict[str, list[str]] = {"en": [], "ja": []}
    land_filter_entries: list[dict] = []
    for rec in browse_records:
        en_html, en_search = render_landscape_card(
            rec, "en", ui, descriptions_i18n, landscape_i18n, decisions_cfg
        )
        ja_html, ja_search = render_landscape_card(
            rec, "ja", ui, descriptions_i18n, landscape_i18n, decisions_cfg
        )
        rendered_land_cards["en"].append(en_html)
        rendered_land_cards["ja"].append(ja_html)
        source_types = sorted({s["type"] for s in rec.get("windowsBinarySources", []) if s.get("type")})
        land_filter_entries.append({
            "name": rec["name"],
            "distributions": rec.get("distributions", []),
            "sourceTypes": source_types,
            "searchText": {"en": en_search, "ja": ja_search},
        })

    catalog_commit = git_head_commit(repo_root)
    filters_payload = {
        "schemaVersion": 1,
        "generatedUtcDate": eff_date,
        "catalogCommit": catalog_commit,
        "availableMajors": available_majors,
        "postgresqlLifecycle": {m: entry["eol"] for m, entry in sorted(pg_lifecycle.items(), key=lambda kv: int(kv[0]))},
        "extensions": ext_filter_entries,
        "landscape": land_filter_entries,
    }
    filters_bytes = (json.dumps(filters_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    filters_hash = sha256_hex(filters_bytes)[:12]
    filters_filename = f"filters.{filters_hash}.json"

    tpl_dir = repo_root / inputs_cfg["templatesDir"]
    assets_dir = repo_root / inputs_cfg["assetsDir"]
    redirect_tpl = (tpl_dir / "redirect.html").read_text(encoding="utf-8")
    home_tpl = (tpl_dir / "home.html").read_text(encoding="utf-8")
    cli_tpl = (tpl_dir / "cli.html").read_text(encoding="utf-8")

    # Stage everything in a temporary directory first so failures leave existing output untouched
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".build-pages-", dir=str(output_dir.parent)))
    try:
        written_files: dict[str, dict] = {}

        def record_file(rel_path: str, raw: bytes) -> None:
            dest = stage / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            written_files[rel_path] = {"bytes": len(raw), "sha256": sha256_hex(raw)}

        record_file(filters_filename, filters_bytes)
        record_file("styles.css", (assets_dir / "styles.css").read_bytes())
        record_file("site.js", (assets_dir / "site.js").read_bytes())
        record_file("index.html", render_template(redirect_tpl, {"siteBaseUrl": esc(site_base_url)}).encode("utf-8"))

        for lang in ("en", "ja"):
            home_html = render_home_page(
                lang=lang,
                template_text=home_tpl,
                site_base_url=site_base_url,
                filters_filename=filters_filename,
                effective_date=eff_date,
                available_majors=available_majors,
                pg_lifecycle=pg_lifecycle,
                ui=ui,
                cli_meta=cli_meta,
                cli_content=cli_content,
                extensions_html="\n        ".join(rendered_ext_cards[lang]),
                ext_count=len(dist_records),
                landscape_grid_html="\n        ".join(rendered_land_cards[lang]),
                landscape_count=len(browse_records),
            )
            record_file(f"{lang}/index.html", home_html.encode("utf-8"))

            cli_html = render_cli_page(
                lang=lang,
                template_text=cli_tpl,
                site_base_url=site_base_url,
                ui=ui,
                cli_cfg=cli_cfg,
                cli_meta=cli_meta,
                cli_content=cli_content,
                pg_lifecycle=pg_lifecycle,
                direct_records=direct_records,
                standalone_records=standalone_records,
            )
            record_file(f"{lang}/cli.html", cli_html.encode("utf-8"))

        cli_meta_bytes = (json.dumps(cli_meta, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        record_file("cli-release-metadata.json", cli_meta_bytes)

        manifest = {
            "schemaVersion": 1,
            "catalogCommit": catalog_commit,
            "inputsSha256": inputs_sha,
            "effectiveDateUtc": eff_date,
            "postgresqlLifecyclePin": {
                **inputs_cfg["postgresqlLifecycle"],
                "verifiedSnapshotSha256": pg_snap_sha,
            },
            "cliRelease": {
                "tag": cli_meta["tag"],
                "releaseId": cli_meta["releaseId"],
                "tagCommit": cli_meta["tagCommit"],
                "exeSha256": cli_meta["assets"]["exe"]["sha256"],
                "exeSizeBytes": cli_meta["assets"]["exe"]["sizeBytes"],
            },
            "counts": {
                "distributedExtensions": len(dist_records),
                "landscapeRegistry": len(landscape_registry),
                "landscapeDisplayed": len(browse_records),
                "externalDirectRecords": len(direct_records),
                "externalStandaloneRecords": len(standalone_records),
            },
            "filtersFile": filters_filename,
            "files": dict(sorted(written_files.items())),
        }
        write_json(stage / "manifest.json", manifest)

        if output_dir.exists():
            shutil.rmtree(output_dir)
        shutil.move(str(stage), str(output_dir))
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise

    if cli_metadata_path is not None:
        write_json(cli_metadata_path, cli_meta)

    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build static bilingual pgextwin Pages from Catalog inputs.")
    parser.add_argument("--inputs", required=True, type=Path, help="Path to site/inputs.json")
    parser.add_argument("--output", required=True, type=Path, help="Output directory for generated site")
    parser.add_argument("--date", default=None, help="Override effective UTC calendar date (YYYY-MM-DD)")
    parser.add_argument("--cli-metadata", default=None, type=Path, help="Optional extra path to write cli-release-metadata.json")
    parser.add_argument("--fetch-live", action="store_true", help="Fetch pinned GitHub API / raw inputs live instead of bundled snapshots")
    args = parser.parse_args()

    manifest = build_site(
        args.inputs,
        args.output,
        effective_date=args.date,
        cli_metadata_path=args.cli_metadata,
        fetch_live=args.fetch_live,
    )
    print(json.dumps({
        "status": "OK",
        "output": str(args.output),
        "catalogCommit": manifest["catalogCommit"],
        "effectiveDateUtc": manifest["effectiveDateUtc"],
        "filtersFile": manifest["filtersFile"],
        "counts": manifest["counts"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
