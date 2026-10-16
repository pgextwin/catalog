#!/usr/bin/env python3
"""Issue #112: explicit, NONPUBLISHING pg_bigm PG14 historical-P1 verifier.

Separate from the main/promote/workflow_dispatch P1 acceptance path.
Inputs are untrusted local copies of *original* bytes and GET-only evidence.
Only the installed real GitHub CLI can perform Sigstore cryptographic validation.
An exit-0 fixture is never a substitute for an independently executed real audit.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from zipfile import ZipFile, BadZipFile

from distribution_manifest_v1 import (Denied, require, strict_json, canonical,
                                      verify_archive_members, safe_component)
from distribution_release_verify_p1 import (
    PROVENANCE, SPDX, PREDICATES, SIGNER, ISSUER, parse_sums, sha,
)

# Exactly one historically established row. This is not a general legacy exemption.
PIN = {
    "catalog": "2e850bb5e5a3441edaa887fa5f7c378d22aea4c6",
    "catalogRecordBlob": "d89bd5e5cd23c1fc15a620ca1ab95fbfb56d51e0",
    "catalogIndexBlob": "05ee514aa26fbd11009ff35e228b6a326e871b06",
    "repo": "pgextwin/pg_bigm", "repoId": 1405047175,
    "releaseId": 408449466, "assetId": 626562095,
    "sbomAssetId": 626562100, "grypeAssetId": 626562124,
    "sumsAssetId": 626562146,
    "sumsSha256": "e94beee9258f8137d6161f102d8bac0e8045a17fa58e79eb7285fcbfdf3fad0a",
    "assetSize": 29490,
    "asset": "pg_bigm-v1.2-20250903-pg14-windows-x64.zip",
    "zipSha256": "3cd9f0facca96f185a406e795fd28a75acea60bb45ac531c9e06fcbc32e2277d",
    "tag": "v1.2-20250903-windows.2", "major": 14,
    "packaging": "cfbb52f8caf41b2c393a1a34f6011157979af2bb",
    "sourceRef": "refs/heads/release/v1.2-20250903-windows.2",
    "runId": 38007421492, "attempt": 1,
    "pgJobId": 114079409058, "publishJobId": 114082606852,
    "signerSha": "8246f4d3415a48b1ad4af13f421277057886b58f",
    "workflowBlob": "3bd732e97fedb22ef0fc2d672e393c5d39cd19d4",
    "configBlob": "64da9ab9111a46bdf0ebc8d742596ffea0916985",
    "upstreamRepo": "pgbigm/pg_bigm", "upstreamRef": "v1.2-20250903",
    "upstreamVersion": "1.2",
    "upstreamSha": "735dceba0ecdd8ac1aaaaa207226a7102b6bbd71",
    "rootSha256": "65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c",
}
MAX_JSONL = 8 * 1024 * 1024
MAX_BUNDLE = 4 * 1024 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _original_file(directory, name, limit=MAX_JSONL):
    path = directory / name
    require(path.is_file() and not path.is_symlink()
            and 0 < path.stat().st_size <= limit,
            "missing/linked/oversize evidence: " + name)
    return path.read_bytes()


def _json_file(directory, name):
    return strict_json(_original_file(directory, name))


def _same(actual, expected, message):
    require(type(actual) is type(expected) and actual == expected, message)


def validate_fixed_catalog(root, catalog_commit):
    _same(catalog_commit, PIN["catalog"], "wrong immutable Catalog pin")
    ix = _original_file(root, "index.json")
    rec = _original_file(root, "pg_bigm.json")
    _same(_blob_sha(ix), PIN["catalogIndexBlob"], "Catalog index blob mismatch")
    _same(_blob_sha(rec), PIN["catalogRecordBlob"], "Catalog record blob mismatch")
    i, r = strict_json(ix), strict_json(rec)
    require("pg_bigm" in i.get("extensions", []) and r.get("name") == "pg_bigm"
            and r.get("repository") == PIN["repo"] and r.get("architecture") == "x64",
            "invalid immutable Catalog row")
    row = r["postgresql"]["14"]
    _same(row["asset"], PIN["asset"], "wrong PG14 ZIP name")
    _same(row["sha256"], PIN["zipSha256"], "wrong PG14 digest")
    _same(r["latest"]["releaseTag"], PIN["tag"], "wrong Catalog Release tag")
    return r, row


def validate_original_metadata(record, release):
    _same(release.get("id"), PIN["releaseId"], "wrong numeric Release ID")
    _same(release.get("tag_name"), PIN["tag"], "wrong Release tag")
    _same(release.get("target_commitish"), PIN["packaging"], "wrong release source SHA")
    require(release.get("draft") is False and release.get("prerelease") is False
            and release.get("html_url") == record["latest"]["releaseUrl"]
            and release.get("published_at") == record["latest"]["publishedAt"],
            "wrong Release publication")
    assets = release.get("assets")
    require(type(assets) is list and len(assets) == 16, "not original 16-asset metadata")
    names = [a.get("name") for a in assets if type(a) is dict]
    require(len(names) == 16 and len(set(names)) == 16, "duplicate Release names")
    ids = [a.get("id") for a in assets]
    require(len(set(ids)) == 16, "duplicate Release asset IDs")
    by_name = {a["name"]: a for a in assets}
    required = {"SHA256SUMS.txt"}
    for major, row in record["postgresql"].items():
        if row.get("available") is not True:
            continue
        required.add(row["asset"])
        require(row["asset"] in by_name, "missing original PG ZIP")
        _same(by_name[row["asset"]]["digest"], "sha256:" + row["sha256"],
              "original ZIP digest disagrees with pinned Catalog")
        for kind in ("sbom", "vulnerabilityReport"):
            e = row["evidence"][kind]
            require(e.get("available") is True and e["asset"] in by_name,
                    "missing Catalog evidence asset")
            _same(by_name[e["asset"]]["digest"], "sha256:" + e["sha256"],
                  "original SPDX/Grype digest disagrees with pinned Catalog")
            required.add(e["asset"])
    _same(set(by_name), required, "incomplete/mixed 16 Release assets")
    _same(by_name["SHA256SUMS.txt"]["digest"], "sha256:" + PIN["sumsSha256"],
          "external original SHA256SUMS digest mismatch")
    for name, key in (("SHA256SUMS.txt", "sumsAssetId"),
                      (record["postgresql"]["14"]["evidence"]["sbom"]["asset"],
                       "sbomAssetId"),
                      (record["postgresql"]["14"]["evidence"]["vulnerabilityReport"]["asset"],
                       "grypeAssetId")):
        _same(by_name[name]["id"], PIN[key], "wrong original evidence Asset ID")
    for a in assets:
        name = a["name"]
        require(type(a.get("id")) is int and a["id"] > 0
                and type(a.get("size")) is int and a["size"] > 0
                and a.get("state") == "uploaded"
                and type(a.get("digest")) is str
                and re.fullmatch(r"sha256:[a-f0-9]{64}", a["digest"])
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name),
                "invalid Release asset metadata")
        _same(a.get("browser_download_url"),
              "https://github.com/" + PIN["repo"] + "/releases/download/"
              + PIN["tag"] + "/" + name, "Release download URL mismatch")
    z = by_name[PIN["asset"]]
    for key, expected in (("id", PIN["assetId"]), ("size", PIN["assetSize"]),
                          ("digest", "sha256:" + PIN["zipSha256"])):
        _same(z[key], expected, "ZIP Asset pin mismatch")
    return by_name



def parse_original_historical_sums(data):
    """Exact original pg_bigm checksum convention, not a general P1 relaxation.

    This one pinned historical Release uses precisely fifteen entries of the
    form 'SHA256  ./basename'. Remove only this literal transport spelling,
    reject collisions/ambiguous paths, then delegate digest parsing to the
    unchanged strict P1 parse_sums(). The signed original file is not changed.
    """
    require(type(data) is bytes and 0 < len(data) <= 8192,
            "invalid historical checksum byte size")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise Denied("historical SHA256SUMS non-ASCII") from exc
    require(len(lines) == 15, "historical Release must contain 15 checksums")
    normalized = []
    seen = set()
    for line in lines:
        match = re.fullmatch(r"([a-f0-9]{64})  \./([A-Za-z0-9][A-Za-z0-9_.-]*)",
                             line)
        require(match is not None, "invalid historical checksum path")
        name = safe_component(match[2])
        folded = name.casefold()
        require(folded not in seen, "duplicate/case-colliding historical checksum")
        seen.add(folded)
        normalized.append(match[1] + "  " + name)
    # Reuse ordinary P1 parsing and duplicate-digest checks with canonical
    # basenames, but do not loosen the ordinary P1 parser itself.
    return parse_sums(("\n".join(normalized) + "\n").encode("ascii"))


def validate_row_bytes(root, record, row, assets):
    folder = root / "assets"
    require(folder.is_dir() and not folder.is_symlink(), "invalid asset directory")
    names = [PIN["asset"], "SHA256SUMS.txt",
             row["evidence"]["sbom"]["asset"],
             row["evidence"]["vulnerabilityReport"]["asset"]]
    _same({p.name for p in folder.iterdir()}, set(names),
          "row audit cannot contain extra assets")
    for name in names:
        blob = _original_file(folder, name, 64 * 1024 * 1024)
        meta = assets[name]
        _same(len(blob), meta["size"], "asset size differs: " + name)
        _same(hashlib.sha256(blob).hexdigest(), meta["digest"][7:],
              "asset bytes differ: " + name)
    sums = parse_original_historical_sums(_original_file(folder, "SHA256SUMS.txt"))
    _same(set(sums), set(assets) - {"SHA256SUMS.txt"},
          "external SHA256SUMS not complete original 15 entries")
    for name, digest in sums.items():
        _same(digest, assets[name]["digest"][7:], "checksum/Release mismatch: " + name)
    sbom = _json_file(folder, names[2])
    grype = _json_file(folder, names[3])
    require(sbom.get("spdxVersion") == "SPDX-2.3"
            and type(grype.get("matches")) is list, "SPDX/Grype invalid")
    path = folder / PIN["asset"]
    try:
        with ZipFile(path) as z:
            verify_archive_members(z)
            require(len([x for x in z.infolist() if x.filename == "PACKAGE-INFO.json"]) == 1,
                    "ambiguous PACKAGE-INFO")
            require(z.getinfo("PACKAGE-INFO.json").file_size <= 262144,
                    "PACKAGE-INFO oversized")
            for entry in z.infolist():
                if not entry.is_dir():
                    with z.open(entry) as stream:
                        while stream.read(1024 * 1024):
                            pass
            pkg = strict_json(z.read("PACKAGE-INFO.json").decode("utf-8-sig"))
    except (BadZipFile, OSError, UnicodeError, RuntimeError, KeyError) as exc:
        raise Denied("ZIP/CRC/PACKAGE-INFO invalid") from exc
    return sbom, pkg


def validate_package_and_origin(root, pkg):
    workflow = _original_file(root, "windows.yml")
    config = _original_file(root, "extension.json")
    _same(_blob_sha(workflow), PIN["workflowBlob"], "not original windows.yml at packaging SHA")
    _same(_blob_sha(config), PIN["configBlob"], "not original config at packaging SHA")
    w = workflow.decode("utf-8")
    require("push:" in w and '"release/**"' in w
            and "uses: " + SIGNER + "@" + PIN["signerSha"] in w
            and "needs: release_build" in w
            and "release_build:" in w and "release:" in w,
            "unexpected historical workflow")
    c = strict_json(config)
    _same(c.get("name"), "pg_bigm", "config name mismatch")
    for field, expected in (("repository", PIN["upstreamRepo"]),
                            ("ref", PIN["upstreamRef"]),
                            ("version", PIN["upstreamVersion"])):
        _same(c["upstream"].get(field), expected, "original config upstream mismatch")
    require("commit" not in c["upstream"], "historical config unexpectedly contains commit")
    require(c["postgresql"]["minMajor"] <= 14 <= c["postgresql"]["maxMajor"],
            "PG14 not in historical config")
    _same(pkg.get("schemaVersion"), 1, "PACKAGE-INFO schema mismatch")
    _same(pkg.get("buildMode"), "release-attested", "unsigned PACKAGE-INFO")
    for field, expected in (("name", "pg_bigm"), ("platform", "windows"),
                            ("architecture", "x64")):
        _same((pkg.get("package") or {}).get(field), expected,
              "PACKAGE-INFO package mismatch")
    _same((pkg.get("postgresql") or {}).get("major"), 14, "wrong PG major")
    _same((pkg.get("source") or {}).get("packagingRepository"),
          PIN["repo"], "packaging repo mismatch")
    _same((pkg.get("source") or {}).get("packagingCommit"),
          PIN["packaging"], "packaging SHA mismatch")
    for field, expected in (("repository", PIN["upstreamRepo"]),
                            ("ref", PIN["upstreamRef"]),
                            ("version", PIN["upstreamVersion"]),
                            ("commit", PIN["upstreamSha"])):
        _same((pkg.get("upstream") or {}).get(field), expected,
              "signed PACKAGE-INFO upstream mismatch")
    run = pkg.get("workflowRun") or {}
    for field, expected in (("id", PIN["runId"]), ("attempt", PIN["attempt"]),
                            ("ref", PIN["sourceRef"]), ("event", "push")):
        _same(run.get(field), expected, "PACKAGE-INFO run/ref/attempt mismatch")
    _same(run.get("url"),
          "https://github.com/" + PIN["repo"] + "/actions/runs/" + str(PIN["runId"]),
          "PACKAGE-INFO run URL mismatch")
    infra = pkg.get("buildInfrastructure") or {}
    _same(infra.get("repository"), "pgextwin/build", "builder repo mismatch")
    _same(infra.get("workflow"), ".github/workflows/build-extension-attested.yml",
          "builder workflow mismatch")
    _same(infra.get("commit"), PIN["signerSha"], "builder SHA mismatch")


def validate_run_jobs(root):
    run = _json_file(root, "run.json")
    for field, expected in (("id", PIN["runId"]), ("run_attempt", PIN["attempt"]),
                            ("path", ".github/workflows/windows.yml"), ("event", "push"),
                            ("head_sha", PIN["packaging"]),
                            ("head_branch", PIN["sourceRef"][11:]),
                            ("status", "completed"), ("conclusion", "success")):
        _same(run.get(field), expected, "historical run mismatch: " + field)
    _same((run.get("repository") or {}).get("id"), PIN["repoId"],
          "historical run Repo ID mismatch")
    _same((run.get("repository") or {}).get("full_name"), PIN["repo"],
          "historical run repository mismatch")
    jobs = _json_file(root, "jobs.json")
    require(type(jobs) is dict and type(jobs.get("jobs")) is list
            and len(jobs["jobs"]) >= 2 and len(jobs["jobs"]) <= 100,
            "missing/ambiguous job listing")
    by_id = {j.get("id"): j for j in jobs["jobs"] if type(j) is dict}
    _same(len(by_id), len(jobs["jobs"]), "duplicate job IDs")
    for ident, name in ((PIN["pgJobId"], "release_build / PostgreSQL 14 / Windows x64"),
                        (PIN["publishJobId"], "release / Publish GitHub Release")):
        job = by_id.get(ident) or {}
        _same(job.get("name"), name, "wrong historical job")
        _same(job.get("conclusion"), "success", "historical job failed")
        _same(job.get("run_attempt"), PIN["attempt"], "mixed job attempt")
        _same(job.get("head_sha"), PIN["packaging"], "mixed job SHA")
    log = _original_file(root, "pg14-job.log", 8 * 1024 * 1024).decode("utf-8-sig")
    # Contemporaneous checkout output is corroboration, NOT signing evidence.
    require("repository: " + PIN["upstreamRepo"] in log
            and "ref: " + PIN["upstreamRef"] in log
            and PIN["upstreamSha"] in log
            and "Complete job name: release_build / PostgreSQL 14 / Windows x64" in log,
            "original upstream checkout log missing or conflicting")
    obj = _json_file(root, "upstream-commit.json")
    _same(obj.get("sha"), PIN["upstreamSha"], "upstream commit object SHA mismatch")
    require(type(obj.get("parents")) is list, "no upstream immutable commit object")


def normalize_jsonl(data, *, name, digest):
    """Return two UNTRUSTED raw Sigstore bundle byte strings, with receipt hashes.

    Transport wrapper must be exactly {'bundle': bundle}. Signed DSSE bytes,
    certificate and transparency material are never modified; only their
    enclosing JSON representation is serialized to gh's raw bundle format.
    """
    require(type(data) is bytes and 0 < len(data) <= MAX_JSONL, "bundle listing size invalid")
    rows = data.splitlines()
    require(len(rows) == 2 and all(0 < len(r) <= MAX_BUNDLE for r in rows),
            "exactly two bounded attestations required")
    raw, receipts = {}, {}
    for line in rows:
        wrapped = strict_json(line)
        require(type(wrapped) is dict and set(wrapped) == {"bundle"},
                "unknown or missing outer JSONL fields")
        bundle = wrapped["bundle"]
        require(type(bundle) is dict
                and set(bundle) == {"mediaType", "dsseEnvelope", "verificationMaterial"}
                and bundle["mediaType"] == "application/vnd.dev.sigstore.bundle.v0.3+json"
                and type(bundle["verificationMaterial"]) is dict,
                "unknown/missing Sigstore bundle fields")
        env = bundle["dsseEnvelope"]
        require(type(env) is dict
                and set(env) == {"payload", "payloadType", "signatures"}
                and env["payloadType"] == "application/vnd.in-toto+json"
                and type(env["signatures"]) is list and len(env["signatures"]) == 1,
                "invalid DSSE envelope/signature cardinality")
        signature = env["signatures"][0]
        require(type(signature) is dict and set(signature) <= {"sig", "keyid"}
                and type(signature.get("sig")) is str and signature["sig"],
                "missing/unknown DSSE signature")
        try:
            payload = base64.b64decode(env["payload"], validate=True)
            base64.b64decode(signature["sig"], validate=True)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise Denied("invalid DSSE base64") from exc
        require(len(payload) <= MAX_BUNDLE, "oversized DSSE statement")
        st = strict_json(payload)
        require(type(st) is dict and set(st) == {"_type", "subject", "predicateType", "predicate"}
                and st.get("_type") ==
                "https://in-toto.io/Statement/v1", "not in-toto v1 statement")
        predicate = st.get("predicateType")
        require(predicate in PREDICATES and predicate not in raw,
                "duplicate/mixed Sigstore predicate")
        subjects = st.get("subject")
        require(type(subjects) is list and len(subjects) == 1
                and type(subjects[0]) is dict
                and subjects[0].get("name") == name
                and subjects[0].get("digest") == {"sha256": digest},
                "wrong signed subject name/digest")
        if predicate == SPDX:
            require((st.get("predicate") or {}).get("spdxVersion") == "SPDX-2.3",
                    "wrong SPDX version")
        else:
            require(type(st.get("predicate")) is dict and
                    type(st["predicate"].get("buildDefinition")) is dict and
                    type(st["predicate"].get("runDetails")) is dict,
                    "wrong SLSA provenance structure")
        material = bundle["verificationMaterial"]
        require(set(material) <= {"certificate", "x509CertificateChain",
                                   "tlogEntries", "timestampVerificationData",
                                   "publicKeyIdentifier"}
                and type(material.get("tlogEntries")) is list
                and bool(material["tlogEntries"])
                and (type(material.get("certificate")) is dict
                     or type(material.get("x509CertificateChain")) is dict),
                "unknown/missing transparency/certificate material")
        bytes_out = canonical(bundle).rstrip(b"\n")
        require(strict_json(bytes_out) == bundle, "bundle serialization changed object")
        raw[predicate] = bytes_out
        receipts[predicate] = {"sourceLineSha256": hashlib.sha256(line).hexdigest(),
                               "rawBundleSha256": hashlib.sha256(bytes_out).hexdigest(),
                               "objectSha256": hashlib.sha256(canonical(bundle)).hexdigest()}
    _same(set(raw), set(PREDICATES), "SLSA and SPDX both required")
    require(raw[PROVENANCE] != raw[SPDX], "duplicate bundle contents")
    return raw, {"wrapperSha256": hashlib.sha256(data).hexdigest(),
                 "normalized": receipts}


def _certified(results, *, predicate, sbom):
    """Policy for genuine gh result; no standalone cryptographic claim."""
    require(type(results) is list and len(results) == 1, "not one verified attestation")
    v = results[0].get("verificationResult") if type(results[0]) is dict else None
    require(type(v) is dict and type(v.get("statement")) is dict
            and type(v.get("signature")) is dict, "malformed gh verified output")
    st = v["statement"]
    _same(st.get("predicateType"), predicate, "wrong verified predicate")
    _same(st.get("subject"), [{"name": PIN["asset"],
                                "digest": {"sha256": PIN["zipSha256"]}}],
          "wrong verified subject")
    require(type(v.get("verifiedTimestamps")) is list and v["verifiedTimestamps"],
            "no verified timestamp")
    cert = v["signature"].get("certificate")
    require(type(cert) is dict, "missing verified certificate")
    signer = "https://github.com/" + SIGNER + "@" + PIN["signerSha"]
    run_url = ("https://github.com/" + PIN["repo"] + "/actions/runs/"
               + str(PIN["runId"]) + "/attempts/" + str(PIN["attempt"]))
    expected = {
        "issuer": ISSUER, "sourceRepositoryURI": "https://github.com/" + PIN["repo"],
        "sourceRepositoryIdentifier": str(PIN["repoId"]),
        "sourceRepositoryDigest": PIN["packaging"], "sourceRepositoryRef": PIN["sourceRef"],
        "runInvocationURI": run_url, "buildTrigger": "push",
        "buildSignerURI": signer, "subjectAlternativeName": signer,
        "buildSignerDigest": PIN["signerSha"],
        "githubWorkflowSHA": PIN["packaging"], "githubWorkflowRef": PIN["sourceRef"],
        "buildConfigURI": ("https://github.com/" + PIN["repo"]
                           + "/.github/workflows/windows.yml@" + PIN["sourceRef"]),
        "buildConfigDigest": PIN["packaging"],
    }
    for key, value in expected.items():
        _same(str(cert.get(key)), str(value), "historical X.509 claim: " + key)
    pred = st.get("predicate")
    require(type(pred) is dict, "missing signed predicate")
    if predicate == SPDX:
        _same(pred, sbom, "SPDX signed predicate and original SPDX asset disagree")
    else:
        _same((pred.get("runDetails") or {}).get("metadata", {}).get("invocationId"),
              run_url, "SLSA run attempt mismatch")
        require(type(pred.get("buildDefinition")) is dict
                and bool((pred.get("runDetails") or {}).get("builder", {}).get("id")),
                "SLSA builder/predicate missing")


def verify_offline_gh(zip_path, sbom, bundles, root):
    """Always invokes REAL gh; don't patch/mimic this for acceptance evidence."""
    require(root.is_file() and not root.is_symlink()
            and sha(root) == PIN["rootSha256"], "untrusted/rotated pinned root")
    receipts = {}
    with tempfile.TemporaryDirectory(prefix="pgextwin-p1-historical-") as temp:
        for predicate in PREDICATES:
            path = Path(temp) / ("slsa.json" if predicate == PROVENANCE else "spdx.json")
            path.write_bytes(bundles[predicate])
            command = ["gh", "attestation", "verify", str(zip_path),
                       "--repo", PIN["repo"], "--bundle", str(path),
                       "--custom-trusted-root", str(root),
                       "--signer-workflow", SIGNER,
                       "--signer-digest", PIN["signerSha"],
                       "--source-ref", PIN["sourceRef"],
                       "--source-digest", PIN["packaging"],
                       "--cert-oidc-issuer", ISSUER,
                       "--predicate-type", predicate, "--format", "json"]
            try:
                result = subprocess.run(command, capture_output=True, text=True,
                                        check=False, timeout=180,
                                        env={**os.environ, "GH_NO_UPDATE_NOTIFIER": "1",
                                             "GH_PROMPT_DISABLED": "1"})
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise Denied("official gh verifier unavailable") from exc
            require(result.returncode == 0, "real Sigstore verification failed")
            _certified(strict_json(result.stdout), predicate=predicate, sbom=sbom)
            receipts[predicate] = hashlib.sha256(bundles[predicate]).hexdigest()
    return receipts


def audit(root, root_path, catalog_commit, *, real_crypto=True):
    """Strict single-row proof, never a Release-wide or fleet approval."""
    require(root.is_dir() and not root.is_symlink(), "invalid private snapshot")
    record, row = validate_fixed_catalog(root, catalog_commit)
    assets = validate_original_metadata(record, _json_file(root, "release.json"))
    sbom, pkg = validate_row_bytes(root, record, row, assets)
    validate_package_and_origin(root, pkg)
    validate_run_jobs(root)
    raw, receipt = normalize_jsonl(_original_file(root, PIN["asset"] + ".jsonl"),
                                   name=PIN["asset"], digest=PIN["zipSha256"])
    require(real_crypto, "without real gh: BLOCKED (fixtures are not signatures)")
    proofs = verify_offline_gh(root / "assets" / PIN["asset"], sbom, raw, root_path)
    return {
        "profile": "historical-pg_bigm-pg14/1", "catalogCommit": catalog_commit,
        "repoId": PIN["repoId"], "releaseId": PIN["releaseId"],
        "assetId": PIN["assetId"], "assetSha256": PIN["zipSha256"],
        "packagingSha": PIN["packaging"], "runId": PIN["runId"],
        "attempt": PIN["attempt"], "signerSha": PIN["signerSha"],
        "upstreamCommit": PIN["upstreamSha"],
        "originalRootSha256": PIN["rootSha256"],
        "bundleNormalization": receipt, "verifiedBundleSha256": proofs,
        "integrityVerified": True, "signatureVerified": True,
        "rowEvidenceComplete": True, "all16AssetsRehashed": False,
        "fleetComplete": False, "publicationAuthorized": False,
        "distributionAuthorized": False,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--historical-pg-bigm-pg14", action="store_true", required=True)
    p.add_argument("--snapshot", type=Path, required=True)
    p.add_argument("--trusted-root", type=Path, required=True)
    p.add_argument("--catalog-commit", required=True)
    a = p.parse_args(argv)
    try:
        print(json.dumps(audit(a.snapshot, a.trusted_root, a.catalog_commit),
                         sort_keys=True, indent=2))
        return 0
    except (Denied, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(json.dumps({"profile": "historical-pg_bigm-pg14/1",
                          "result": "BLOCKED", "reason": str(exc),
                          "signatureVerified": False, "publicationAuthorized": False},
                         sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
