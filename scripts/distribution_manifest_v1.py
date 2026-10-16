#!/usr/bin/env python3
"""Issue #112 P0: inert, deterministic Catalog -> distribution manifest projection.

No HTTP, gh CLI, subprocess, signing, downloads, unpacking or publishing.
A caller MUST authenticate the exact Catalog Git tree and run an independent
byte-and-Sigstore verifier before supplying a trusted verification callback.
Self-reported JSON receipts are NOT proof. The default cannot mark bytes verified.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import PurePosixPath
import re
from zipfile import ZipFile

from jsonschema import Draft202012Validator, FormatChecker

try:
    from .verified_release_record import ALLOWED
except ImportError:
    from verified_release_record import ALLOWED

VERSION = "pgextwin-distribution-manifest/v1"
GENERATOR = "pgextwin-manifest-p0/1"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
MAJOR = re.compile(r"(?:[1-9][0-9]*)\Z")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SCHEMA_FILE = "schema/distribution-manifest-v1.schema.json"
MAX_MEMBERS = 1000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024
MAX_RATIO = 200


class Denied(ValueError):
    """Refuse ambiguous or untrusted source/manifest/ZIP."""


def require(ok, message):
    if not ok:
        raise Denied(message)


def strict_json(blob):
    """Reject duplicate keys instead of silently accepting overwritten identities."""
    def no_duplicate(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "duplicate JSON key: " + key)
            out[key] = value
        return out
    try:
        return json.loads(blob, object_pairs_hook=no_duplicate,
                          parse_constant=lambda x: (_ for _ in ()).throw(Denied("nonfinite JSON")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Denied("invalid JSON") from exc


def sha256(blob):
    return hashlib.sha256(blob).hexdigest()


def canonical(data):
    """JSON bytes stable across platforms and insertion order."""
    return (json.dumps(data, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def safe_component(s):
    require(isinstance(s, str) and bool(COMPONENT.fullmatch(s))
            and s not in (".", "..") and not s.endswith(".") and len(s) <= 160
            and s.split(".")[0].upper() not in
            {"CON", "PRN", "AUX", "NUL", *(("COM" + str(i)) for i in range(1, 10)),
             *(("LPT" + str(i)) for i in range(1, 10))},
            "unsafe path component")
    return s


def safe_path(s):
    require(isinstance(s, str) and s and len(s) <= 768
            and "\\" not in s and "\x00" not in s
            and not s.startswith("/") and ":" not in s,
            "unsafe relative path")
    parts = s.split("/")
    for part in parts:
        safe_component(part)
    require(str(PurePosixPath(s)) == s, "noncanonical path")
    return s


def iso_utc(value):
    require(isinstance(value, str) and STAMP.fullmatch(value),
            "timestamp must be exact UTC seconds")
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Denied("invalid UTC timestamp") from exc
    require(d.tzinfo == timezone.utc and d.strftime("%Y-%m-%dT%H:%M:%SZ") == value,
            "timestamp not canonical UTC")
    return d


def major_key(s):
    require(isinstance(s, str) and MAJOR.fullmatch(s), "invalid PG major")
    return int(s)


def unique_names(items):
    names = [a.get("name") for a in items]
    require(all(isinstance(n, str) for n in names) and len(set(names)) == len(names),
            "duplicate Release asset")
    for n in names:
        safe_component(n)
    return {x["name"]: x for x in items}


def checksummed_asset(assets, name, digest):
    safe_component(name)
    require(isinstance(digest, str) and HEX64.fullmatch(digest),
            "missing Catalog SHA256")
    a = assets.get(name)
    require(isinstance(a, dict) and type(a.get("id")) is int
            and a["id"] > 0 and a.get("state") == "uploaded"
            and a.get("digest") == "sha256:" + digest
            and a.get("name") == name,
            "Release asset identity/digest mismatch: " + name)
    return a


def archive_path(extension, major, version, name):
    return safe_path("packages/pg" + major + "/" + safe_component(extension)
                     + "/" + safe_component(version) + "/" + safe_component(name))


def verify_archive_members(zf: ZipFile):
    """Inspection only, never extract. Reject traversal/links/duplicates/bombs."""
    infos = zf.infolist()
    require(len(infos) <= MAX_MEMBERS, "too many ZIP members")
    names = set()
    all_bytes = 0
    for member in infos:
        name = member.filename
        safe_path(name.rstrip("/") if name.endswith("/") else name)
        folded = name.casefold()
        require(folded not in names, "duplicate/case-colliding ZIP entry")
        names.add(folded)
        mode = (member.external_attr >> 16) & 0o170000
        require(mode not in (0o120000, 0o060000, 0o020000, 0o010000),
                "ZIP link or special file forbidden")
        require(member.flag_bits & 0x1 == 0, "encrypted ZIP forbidden")
        require(member.file_size <= MAX_MEMBER_BYTES and member.file_size >= 0,
                "oversized ZIP member")
        if not member.is_dir():
            require(member.compress_size > 0 or member.file_size == 0,
                    "invalid ZIP compression")
            if member.file_size:
                require(member.file_size / member.compress_size <= MAX_RATIO,
                        "ZIP compression bomb")
        all_bytes += member.file_size
        require(all_bytes <= MAX_UNCOMPRESSED_BYTES, "oversized ZIP payload")
    files = {n.rstrip("/").casefold() for n in (i.filename for i in infos) if not n.endswith("/")}
    for n in files:
        require(not any(other.startswith(n + "/") for other in names),
                "ZIP file/directory collision")
    return len(infos)


def assert_schema(manifest, schema):
    Draft202012Validator.check_schema(schema)
    errs = sorted(Draft202012Validator(schema, format_checker=FormatChecker())
                  .iter_errors(manifest), key=lambda e: str(e.absolute_path))
    require(not errs, "manifest schema: " + (errs[0].message if errs else ""))


def validate_manifest(manifest, schema):
    """Reject replacement, reordering, untrusted trust-level assertions and stale IDs."""
    assert_schema(manifest, schema)
    require(manifest["publicationAuthorized"] is False
            and manifest["trust"]["offlineTrustRoot"] == "EXTERNAL_REQUIRED",
            "no publication/trust-anchor authority in P0")
    snapshot = dict(manifest)
    actual = snapshot.pop("snapshotId")
    require(sha256(canonical(snapshot)) == actual, "manifest snapshot substitution")
    pairs = [(p["extension"], major_key(p["pgMajor"])) for p in manifest["packages"]]
    require(pairs == sorted(set(pairs)), "duplicate/unsorted packages")
    coverage = [(c["extension"], major_key(c["pgMajor"])) for c in manifest["coverage"]]
    require(coverage == sorted(set(coverage)), "duplicate/unsorted coverage")
    pset = set(pairs)
    require(pset == {k for k, c in zip(coverage, manifest["coverage"])
                     if c["status"] in ("included", "historical")},
            "package/coverage relationship invalid")
    require(all(p["evidence"]["status"] == "SIGNATURE_VERIFIED" for p in manifest["packages"]),
            "package without independently verified signing proof")
    for p in manifest["packages"]:
        require(p["bundleRelativePath"] == archive_path(p["extension"], p["pgMajor"],
                p["packageVersion"], p["assetName"]), "package destination mismatch")
        require(p["sourceRepository"]["name"] == "pgextwin/" + p["extension"],
                "substituted signer source repository")
        require(p["assetUrl"] == "https://github.com/" + p["sourceRepository"]["name"]
                + "/releases/download/" + p["releaseTag"] + "/" + p["assetName"],
                "substituted official Release URL")
        require(p["evidence"]["subjectSha256"] == p["releaseAssetSha256"],
                "signed subject mismatch")
        require(p["evidence"]["signerWorkflow"] ==
                "pgextwin/build/.github/workflows/build-extension-attested.yml",
                "signer workflow mismatch")
    expected_complete = all(c["status"] in ("included", "historical", "unsupported")
                            for c in manifest["coverage"])
    require(manifest["complete"] == expected_complete, "false COMPLETE claim")
    return True


def build_manifest(*, index_blob, record_blobs, catalog_commit, generated_at,
                   lifecycle, approved_majors, releases, pins, receipts,
                   independently_verify, schema):
    """Construct snapshot from authenticated inputs, no external IO.

    independently_verify is mandatory and must be an implementation that
    independently hashes actual Release bytes and cryptographically validates
    attestation, repo numeric ID, subject, predicate and trusted root.
    This module ships no such implementation: P0 cannot promote untrusted
    self-declarations into SIGNATURE_VERIFIED or create publishable bundles.
    """
    require(HEX40.fullmatch(catalog_commit or ""), "Catalog commit must be immutable SHA")
    iso_utc(generated_at)
    require(callable(independently_verify), "independent byte/signature verifier required")
    index = strict_json(index_blob)
    require(index.get("schemaVersion") == 2
            and index.get("extensions") == sorted(ALLOWED)
            and len(index["extensions"]) == len(ALLOWED),
            "Catalog exact 14-record allowlist mismatch")
    require(set(record_blobs) == set(index["extensions"]),
            "missing/extra Catalog records")
    require(isinstance(lifecycle, list) and lifecycle, "missing PG lifecycle")
    majors = {}
    for pg in lifecycle:
        m = pg.get("major")
        require(type(m) is int and m > 0 and m not in majors,
                "duplicate/unknown PG major")
        try:
            eol = date.fromisoformat(pg["eol"])
        except (KeyError, TypeError, ValueError) as exc:
            raise Denied("invalid PG EOL") from exc
        majors[str(m)] = eol
    # Approved majors must come from an independently authenticated policy,
    # not the self-reported Catalog or untrusted manifest. This allows a
    # later, separately authorized PG19 GA onboarding without code changes.
    require(isinstance(approved_majors, (tuple, list))
            and bool(approved_majors)
            and all(isinstance(m, str) and MAJOR.fullmatch(m) for m in approved_majors)
            and list(approved_majors) == sorted(set(approved_majors), key=int)
            and set(majors) == set(approved_majors),
            "unknown PG major or unauthorized major policy")
    today = iso_utc(generated_at).date()
    packages, coverage, dests = [], [], set()
    for name in index["extensions"]:
        r = strict_json(record_blobs[name])
        require(r.get("schemaVersion") == 2 and r.get("name") == name
                and r.get("repository") == "pgextwin/" + name
                and r.get("architecture") == "x64"
                and r.get("upstream", {}).get("repository") == ALLOWED[name],
                "Catalog record identity mismatch")
        require(set(r.get("postgresql", {})) == set(majors),
                "incomplete/unknown Catalog PG matrix")
        release = releases.get(name)
        require(isinstance(release, dict)
                and release.get("draft") is False and release.get("prerelease") is False
                and release.get("tag_name") == r["latest"]["releaseTag"]
                and release.get("published_at") == r["latest"]["publishedAt"]
                and r["latest"]["releaseUrl"] ==
                "https://github.com/pgextwin/" + name + "/releases/tag/" + release["tag_name"]
                and type(release.get("id")) is int and release["id"] > 0
                and HEX40.fullmatch(release.get("target_commitish", "")),
                "unpublished/stale/substituted Release")
        tag = safe_component(release["tag_name"])
        assets = unique_names(release.get("assets", []))
        require(r["latest"]["checksumsAsset"] == "SHA256SUMS.txt",
                "unexpected checksum asset name")
        checksums = assets.get("SHA256SUMS.txt")
        require(isinstance(checksums, dict) and checksums.get("state") == "uploaded"
                and type(checksums.get("id")) is int and checksums["id"] > 0
                and isinstance(checksums.get("digest"), str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", checksums["digest"]),
                "missing genuine GitHub checksum asset metadata")
        checksum_sha = checksums["digest"][7:]
        for major in sorted(majors, key=int):
            info = r["postgresql"][major]
            eol = majors[major]
            state = "historical" if today > eol else "included"
            row = {"extension": name, "pgMajor": major, "status": "blocked",
                   "reason": "independent signature and source pin required"}
            if info.get("available") is not True:
                row.update(status="missing" if today <= eol else "historical",
                           reason="Catalog has no public binary for this major")
                # No empty historical package is permitted; mark missing historical as blocked.
                if row["status"] == "historical":
                    row["status"] = "blocked"
                coverage.append(row)
                continue
            asset = checksummed_asset(assets, info["asset"], info["sha256"])
            require(info["downloadUrl"] == asset.get("browser_download_url"),
                    "Catalog/Release URL mismatch")
            for ev in ("sbom", "vulnerabilityReport"):
                q = info["evidence"][ev]
                require(q.get("available") is True, "missing SPDX/Grype declaration")
                checksummed_asset(assets, q["asset"], q["sha256"])
                require(q["downloadUrl"] == assets[q["asset"]].get("browser_download_url"),
                        "SPDX/Grype URL mismatch")
            source = pins.get((name, major))
            if not isinstance(source, dict):
                coverage.append(row)
                continue
            u = r["upstream"].get("perPostgresql", {}).get(major, r["upstream"])
            require(source.get("version") == u.get("version")
                    and (not u.get("ref") or source.get("ref") == u["ref"])
                    and HEX40.fullmatch(source.get("commit", ""))
                    and safe_component(source.get("ref", "")),
                    "untrusted per-PG upstream commit/ref/version")
            receipt = receipts.get((name, major))
            if not isinstance(receipt, dict):
                coverage.append(row)
                continue
            require(receipt.get("assetId") == asset["id"]
                    and receipt.get("releaseId") == release["id"]
                    and receipt.get("subjectSha256") == info["sha256"]
                    and receipt.get("signerWorkflow") ==
                    "pgextwin/build/.github/workflows/build-extension-attested.yml"
                    and HEX64.fullmatch(receipt.get("trustedRootSha256", ""))
                    and type(receipt.get("signerRepositoryId")) is int
                    and receipt["signerRepositoryId"] == 1405931353
                    and receipt.get("sourceRef") == "refs/heads/main"
                    and receipt.get("predicateTypes") ==
                    ["https://slsa.dev/provenance/v1", "https://spdx.dev/Document/v2.3"]
                    and all(isinstance(receipt.get(field), str)
                            and HEX64.fullmatch(receipt[field])
                            for field in ("attestationBundleSha256",
                                          "sbomAttestationBundleSha256"))
                    and all(isinstance(receipt.get(field), str)
                            for field in ("attestationBundleName",
                                          "sbomAttestationBundleName")),
                    "untrusted or incomplete attestation receipt")
            iso_utc(receipt.get("verifiedAtUtc"))
            # Critical boundary: caller-injected verifier must not trust the
            # receipt or manifest's own signatureVerified flag.
            if independently_verify(name, major, release, asset, source, receipt) is not True:
                coverage.append(row)
                continue
            bundle_path = archive_path(name, major, source["version"], info["asset"])
            folded = bundle_path.casefold()
            require(folded not in dests, "bundle filename/path collision")
            dests.add(folded)
            source_repo_id = receipt.get("sourceRepositoryId")
            require(type(source_repo_id) is int and source_repo_id > 0,
                    "missing numeric source repo ID")
            p = {
                "extension": name, "pgMajor": major, "architecture": "x64",
                "packageVersion": source["version"], "upstreamRef": source["ref"],
                "upstreamCommitSha": source["commit"],
                "packagingCommitSha": release["target_commitish"],
                "sourceRepository": {"name": "pgextwin/" + name, "id": source_repo_id},
                "releaseTag": tag, "releaseId": release["id"],
                "assetName": asset["name"], "assetId": asset["id"],
                "assetUrl": asset["browser_download_url"],
                "releaseAssetSha256": info["sha256"],
                "checksumsAsset": r["latest"]["checksumsAsset"],
                "checksumsSha256": checksum_sha,
                "catalogRecordSha256": sha256(record_blobs[name]),
                "bundleRelativePath": bundle_path, "pgEol": eol.isoformat(),
                "license": r["license"],
                "licenseNotice": {"state": "UNVERIFIED", "path": None},
                "runtime": r["runtime"]["requirements"],
                "evidence": {
                    "status": "SIGNATURE_VERIFIED",
                    "evidencePresent": True, "cryptographicallyVerified": True,
                    "attestationBundleName": safe_component(receipt["attestationBundleName"]),
                    "attestationBundleSha256": receipt["attestationBundleSha256"],
                    "sbomAttestationBundleName": safe_component(receipt["sbomAttestationBundleName"]),
                    "sbomAttestationBundleSha256": receipt["sbomAttestationBundleSha256"],
                    "spdxAsset": info["evidence"]["sbom"]["asset"],
                    "spdxSha256": info["evidence"]["sbom"]["sha256"],
                    "grypeAsset": info["evidence"]["vulnerabilityReport"]["asset"],
                    "grypeSha256": info["evidence"]["vulnerabilityReport"]["sha256"],
                    "subjectSha256": receipt["subjectSha256"],
                    "signerWorkflow": receipt["signerWorkflow"],
                    "signerRepositoryId": receipt["signerRepositoryId"],
                    "trustedRootSha256": receipt["trustedRootSha256"],
                    "predicateTypes": receipt["predicateTypes"],
                    "verifiedAtUtc": receipt["verifiedAtUtc"],
                },
            }
            packages.append(p)
            row.update(status=state, reason="independent byte and signature verification")
            coverage.append(row)
    packages.sort(key=lambda p: (p["extension"], int(p["pgMajor"])))
    coverage.sort(key=lambda c: (c["extension"], int(c["pgMajor"])))
    data = {
        "schemaVersion": VERSION, "generatedAtUtc": generated_at,
        "catalogCommitSha": catalog_commit, "catalogSchemaVersion": 2,
        "catalogIndexSha256": sha256(index_blob), "generatorVersion": GENERATOR,
        "selectionPolicy": {"platform": "windows", "architecture": "x64",
                            "pgMajors": sorted(majors, key=int),
                            "releaseSource": "published-github-release-only"},
        "trust": {"offlineTrustRoot": "EXTERNAL_REQUIRED",
                  "outerArchiveSigned": False,
                  "scope": "NONPUBLISHING_P0"},
        "packages": packages, "coverage": coverage,
        "complete": all(c["status"] in ("included", "historical", "unsupported")
                        for c in coverage),
        "publicationAuthorized": False,
    }
    data["snapshotId"] = sha256(canonical(data))
    validate_manifest(data, schema)
    return data
