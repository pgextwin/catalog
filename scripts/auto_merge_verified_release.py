#!/usr/bin/env python3
"""Issue #75: fail-closed, fleet-wide merge of independently signed Catalog PRs.

The existing Catalog-only App can merge an existing, *fully reverified* record PR
only. It cannot publish a Windows Release. All code executed here is from the
trusted Catalog main; PR code is NEVER checked out or executed. Default DENY.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

try:
    from scripts.verified_release_record import INTAKE_ALLOWED, FIRST_RELEASE_SOURCES
except ModuleNotFoundError:
    from verified_release_record import INTAKE_ALLOWED, FIRST_RELEASE_SOURCES

REPO = "pgextwin/catalog"
CENTRAL = "pgextwin/build"
CATALOG_ID = 1405939279
CATALOG_APP = "pgextwin-catalog-proposer"
CATALOG_INSTALLATION = "170516730"
SHA = re.compile(r"^[0-9a-f]{40}$")
BRANCH = re.compile(
    r"^auto-catalog/([a-z][a-z0-9_]{1,63})-(v[A-Za-z0-9][A-Za-z0-9._-]{0,110}-windows\.[1-9][0-9]*)$"
)
REQUIRED_CHECKS = frozenset({"validate", "cli-windows-package-smoke"})
ROOT = Path(__file__).resolve().parents[1]


class AutoMergeDenied(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AutoMergeDenied(message)


def gh(*args, env=None):
    result = subprocess.run(("gh",) + args, capture_output=True, text=True, env=env)
    require(result.returncode == 0, "authenticated GitHub request denied: " +
            " ".join(args[:3]) + " " + result.stderr[:200])
    return result.stdout


def api(path):
    env = dict(os.environ)
    if not path.startswith("installation/"):
        # Status/Run/policy GETs use the workflow's independent read credential.
        # The Catalog App token is reserved for scope inspection and PUT merge.
        read_token = env.get("GH_READ_TOKEN")
        require(type(read_token) is str and len(read_token) > 10,
                "independent read credential unavailable")
        env["GH_TOKEN"] = read_token
    return json.loads(gh("api", path, env=env))


def unpack_content(raw):
    require(type(raw) is dict and raw.get("encoding") == "base64"
            and type(raw.get("content")) is str, "trusted contents unavailable")
    # Contents API base64 is line-wrapped. Remove only transport newlines;
    # retain strict validation so corrupt characters still fail closed.
    content = raw["content"].replace("\r", "").replace("\n", "")
    return json.loads(base64.b64decode(content, validate=True).decode("utf-8"))


def verify_app_scope(payload, slug, installation):
    """Pin the trusted token action's identity and its live installation scope."""
    require(slug == CATALOG_APP and installation == CATALOG_INSTALLATION,
            "unknown dedicated Catalog App identity")
    require(type(payload) is dict and type(payload.get("total_count")) is int
            and payload["total_count"] == 1
            and type(payload.get("repositories")) is list
            and len(payload["repositories"]) == 1,
            "Catalog App token is not scoped to exactly one repository")
    repo = payload["repositories"][0]
    require(type(repo) is dict and type(repo.get("id")) is int
            and repo["id"] == CATALOG_ID and repo.get("full_name") == REPO
            and repo.get("private") is False,
            "Catalog App token repository identity differs")


def check_app_scope():
    verify_app_scope(api("installation/repositories?per_page=100"),
                     os.environ.get("PGEXTWIN_CATALOG_APP_SLUG"),
                     os.environ.get("PGEXTWIN_CATALOG_APP_INSTALLATION_ID"))


def revoke_and_confirm():
    # Never print an API response, key or installation token, even on failure.
    result = subprocess.run(("gh", "api", "--method", "DELETE", "installation/token"),
                            capture_output=True, text=True)
    require(result.returncode == 0, "Catalog App token revocation failed")
    after = subprocess.run(("gh", "api", "installation/repositories?per_page=100"),
                           capture_output=True, text=True)
    require(after.returncode != 0 and "HTTP 401" in after.stderr,
            "revoked Catalog App token did not return HTTP401")


def probe_app(output):
    """GET-only capability observation; revoke the token on both allow and deny."""
    try:
        require(os.environ.get("GITHUB_REPOSITORY") == REPO
                and os.environ.get("GITHUB_REF") == "refs/heads/main"
                and os.environ.get("GITHUB_EVENT_NAME") == "workflow_run",
                "untrusted Catalog App proof event")
        check_app_scope()
        branch = api("repos/" + REPO + "/branches/main")
        require(branch.get("protected") is True
                and (branch.get("commit") or {}).get("sha") == os.environ.get("GITHUB_SHA")
                and SHA.fullmatch(os.environ.get("GITHUB_SHA", "")),
                "Catalog App proof is not bound to current protected main")
    finally:
        revoke_and_confirm()
    record = {
        "schemaVersion": 1, "repository": REPO, "repositoryId": CATALOG_ID,
        "sourceSha": os.environ["GITHUB_SHA"], "appSlug": CATALOG_APP,
        "installationId": int(CATALOG_INSTALLATION),
        "requestedTokenPermissions": {"contents": "write", "pull_requests": "write"},
        "scopeVerified": True, "tokenRevokedHttp401": True,
        "repositoryWritePerformed": False, "protectedMergePerformed": False,
        "publicationAuthorized": False, "catalogMergeAuthorized": False,
    }
    Path(output).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print("CATALOG_APP_SCOPE_VERIFIED; TOKEN_REVOKED_HTTP401; NO_REPOSITORY_WRITE; PUBLISH_DENY")


def validate_local_policy(local):
    """Validate a protected deployment declaration without granting merge authority.

    Both disabled and explicitly enabled declarations use the same strict
    identity grammar. Runtime, central, CI and signed-asset gates remain separate.
    """
    local_fields = {
        "schemaVersion", "enabled", "expectedRepository", "centralPolicyRepository",
        "requiredWorkflow", "requiredCheckAppId", "expectedProposerLogin", "expectedProposerBotId", "notes"
    }
    require(type(local) is dict and set(local) == local_fields
            and type(local.get("schemaVersion")) is int
            and local["schemaVersion"] == 2
            and type(local.get("enabled")) is bool
            and type(local.get("notes")) is str
            and local.get("expectedRepository") == REPO
            and local.get("centralPolicyRepository") == CENTRAL
            and local.get("requiredWorkflow") == "validate.yml"
            and type(local.get("requiredCheckAppId")) is int
            and local["requiredCheckAppId"] == 15368
            and local.get("expectedProposerLogin") == "pgextwin-catalog-proposer[bot]"
            and type(local.get("expectedProposerBotId")) is int
            and local["expectedProposerBotId"] == 341259304,
            "Catalog signed merge deployment declaration mismatched")
    return {"enabled": local["enabled"], "catalogMergeAuthorized": False,
            "publicationAuthorized": False}


def verify_policy(local, central):
    """Both independent protected opt-ins required; never infer from Release tags."""
    validate_local_policy(local)
    require(local["enabled"] is True, "Catalog-wide signed merge policy disabled")
    central_fields = {
        "schemaVersion", "enabled", "mode", "releasePolicy",
        "automaticFormalRelease", "automaticCatalogMerge", "allowedExtensions",
        "requiredCatalogWorkflow", "requirePublishedPublicRelease",
        "requireBuildProvenanceAttestation", "requireSbomAttestation",
        "requireExactSHA256", "requireExactHeadRequiredChecks",
        "requireDedicatedMergeApp", "denyUnknownOrDuplicate", "notes"
    }
    require(type(central) is dict and set(central) == central_fields
            and type(central.get("schemaVersion")) is int
            and central["schemaVersion"] == 1
            and central.get("enabled") is True
            and central.get("automaticCatalogMerge") is True
            and central.get("requiredCatalogWorkflow") == "validate.yml"
            and type(central.get("allowedExtensions")) is list
            and set(central["allowedExtensions"]) == set(INTAKE_ALLOWED)
            and len(central["allowedExtensions"]) == len(INTAKE_ALLOWED)
            and all(type(name) is str for name in central["allowedExtensions"])
            and all(central.get(field) is True for field in (
                "requirePublishedPublicRelease", "requireBuildProvenanceAttestation",
                "requireSbomAttestation", "requireExactSHA256",
                "requireExactHeadRequiredChecks", "requireDedicatedMergeApp",
                "denyUnknownOrDuplicate"
            )), "central exact registered signed Catalog approval not satisfied")
    mode = central.get("releasePolicy")
    require((
        mode == "manual-dispatch"
        and central.get("mode") == "POST_MANUAL_RELEASE_ONLY"
        and central.get("automaticFormalRelease") is False
    ) or (
        mode == "automatic-signed-schedule"
        and central.get("mode") == "POST_VERIFIED_RELEASE_ONLY"
        and central.get("automaticFormalRelease") is True
    ), "central signed-release policy and Catalog downstream mode disagree")


def inspect_pr(pr, files, commits, *, proposer_login, proposer_id, initial=False):
    require(type(pr) is dict and pr.get("state") == "open"
            and pr.get("draft") is False and type(pr.get("number")) is int
            and pr["number"] > 0, "untrusted Catalog PR")
    head = pr.get("head") or {}
    match = BRANCH.fullmatch(head.get("ref", ""))
    require(match is not None and type(head.get("sha")) is str
            and SHA.fullmatch(head["sha"]), "unknown Catalog automation branch")
    name, tag = match.groups()
    require(name in INTAKE_ALLOWED, "extension lacks protected signer identity")
    require((pr.get("user") or {}).get("login") == proposer_login
            and (pr.get("user") or {}).get("id") == proposer_id
            and (pr.get("user") or {}).get("type") == "Bot"
            and (pr.get("base") or {}).get("ref") == "main"
            and (head.get("repo") or {}).get("full_name") == REPO
            and pr.get("commits") == 1, "Catalog PR not from dedicated proposer App")
    path = "extensions/" + name + ".json"
    require(type(files) is list, "Catalog PR file inventory unavailable")
    actual = {row.get("filename"): row.get("status") for row in files}
    require(len(actual) == len(files), "duplicate Catalog PR file paths")
    # First Release requires initial index/landscape changes and remains a
    # manual protected-merge decision even when the runtime opt-in is true.
    require(initial is False, "first Catalog Release auto-merge forbidden")
    require(actual == {path: "modified"},
            "existing Catalog PR is not record-only")
    expected = "catalog: verified operator release " + name + " " + tag
    require(type(commits) is list and len(commits) == 1
            and (commits[0].get("commit") or {}).get("message", "").split("\n")[0] == expected,
            "Catalog proposal does not match signed-proposer commit contract")
    return pr["number"], head["sha"], head["ref"], name, tag


def validate_run(runs, sha, branch):
    require(type(runs) is list and 0 < len(runs) < 100, "PR validation inventory incomplete")
    relevant = [run for run in runs
                if run.get("head_sha") == sha and run.get("head_branch") == branch
                and run.get("event") == "pull_request"]
    require(bool(relevant), "native exact-head pull_request validation missing")
    latest = max(relevant, key=lambda run: (run.get("created_at", ""), run.get("id", 0)))
    require(latest.get("status") == "completed"
            and latest.get("conclusion") == "success"
            and latest.get("run_attempt") == 1, "latest native PR CI not attempt1 SUCCESS")


def validate_checks(payload, sha):
    """Do not accept a green workflow name without the actual required App."""
    require(type(payload) is dict and type(payload.get("check_runs")) is list
            and len(payload["check_runs"]) < 100
            and payload.get("total_count") == len(payload["check_runs"]),
            "exact-head required check collection unavailable or paginated")
    matched = {}
    for run in payload["check_runs"]:
        name = run.get("name")
        if name not in REQUIRED_CHECKS:
            continue
        require(name not in matched, "duplicate required status check name")
        matched[name] = run
    require(set(matched) == REQUIRED_CHECKS, "required native Windows Catalog checks missing")
    for run in matched.values():
        require(run.get("head_sha") == sha and run.get("status") == "completed"
                and run.get("conclusion") == "success"
                and (run.get("app") or {}).get("id") == 15368,
                "required App15368 native check not completed SUCCESS")


def first_release_projection(name, verified):
    """Recompute first-intake index and landscape from protected main, never PR code."""
    require(name in FIRST_RELEASE_SOURCES
            and verified.get("schemaVersion") == 2
            and verified.get("name") == name
            and verified.get("repository") == "pgextwin/" + name
            and (verified.get("upstream") or {}).get("repository") == FIRST_RELEASE_SOURCES[name],
            "unknown first-intake identity")
    index = json.loads(Path("index.json").read_text(encoding="utf-8"))
    require(index.get("schemaVersion") == 2
            and type(index.get("extensions")) is list
            and index["extensions"] == sorted(set(index["extensions"]))
            and name not in index["extensions"],
            "first-intake index is not a protected unregistered source")
    index["extensions"] = sorted(index["extensions"] + [name])
    li = json.loads(Path("landscape/index.json").read_text(encoding="utf-8"))
    require(li.get("schemaVersion") == 1
            and type(li.get("extensions")) is list
            and li["extensions"] == sorted(set(li["extensions"])),
            "invalid protected landscape registry")
    previous = Path("landscape/extensions") / (name + ".json")
    landscape = json.loads(previous.read_text(encoding="utf-8")) if previous.is_file() else {}
    latest = verified.get("latest") or {}
    release_url = latest.get("releaseUrl")
    published_at = latest.get("publishedAt")
    require(type(release_url) is str
            and release_url.startswith("https://github.com/pgextwin/" + name + "/releases/tag/")
            and type(published_at) is str and len(published_at) >= 10,
            "missing independently verified public first-Release identity")
    landscape.update(
        schemaVersion=1, name=name, displayName=verified["displayName"],
        description=verified["description"],
        upstreamRepository=FIRST_RELEASE_SOURCES[name],
        status="implemented", pgextwinCatalogName=name,
        lastReviewed=published_at[:10],
        evidenceUrls=[release_url, "https://github.com/" + FIRST_RELEASE_SOURCES[name]],
        windowsBinarySources=[])
    for key in ("candidateRationale", "roadmap", "notPlannedReason",
                "notPlannedReasonJa", "reasonCode"):
        landscape.pop(key, None)
    li["extensions"] = sorted(set(li["extensions"]) | {name})
    return {"index.json": index, "landscape/index.json": li,
            "landscape/extensions/" + name + ".json": landscape}


def verify_record(name, tag, head_sha, *, read_token, files=None):
    """Reverify exact signed bytes before comparing an existing or FIRST Catalog PR."""
    require(name in INTAKE_ALLOWED and SHA.fullmatch(head_sha)
            and type(read_token) is str and len(read_token) > 10,
            "unsigned verifier input or read token missing")
    path = "extensions/" + name + ".json"
    initial = not Path(path).is_file()
    require(not initial, "first Catalog Release signed verification cannot authorize auto-merge")
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        (temp / "extensions").mkdir()
        candidate = temp / path
        if not initial:
            candidate.write_bytes(Path(path).read_bytes())
        env = dict(os.environ, GH_TOKEN=read_token)
        run = subprocess.run(
            (sys.executable, str(ROOT / "scripts" / "verify_signed_fleet_release.py"),
             "--extension", name, "--release-tag", tag, "--record-output", path),
            cwd=temp, env=env, text=True, capture_output=True
        )
        require(run.returncode == 0 and candidate.is_file(),
                "fresh signed public Release verification DENY: " + run.stderr[:300])
        verified = json.loads(candidate.read_text(encoding="utf-8"))
    if not initial:
        original = json.loads(Path(path).read_text(encoding="utf-8"))
        require(verified != original, "signed Release already in Catalog/no-op")
    proposed = unpack_content(api("repos/" + REPO + "/contents/" + path +
                                  "?ref=" + head_sha))
    require(proposed == verified, "PR record differs from independently signed public bytes")
    if initial:
        expected = first_release_projection(name, verified)
        # The Landscape index may already register the extension as a prospect:
        # then the proposer must NOT invent a no-op fourth diff.
        changed = {path, "index.json", "landscape/extensions/" + name + ".json"}
        old_li = json.loads(Path("landscape/index.json").read_text(encoding="utf-8"))
        if expected["landscape/index.json"] != old_li:
            changed.add("landscape/index.json")
        if files is not None:
            require({entry.get("filename") for entry in files} == changed,
                    "first-intake PR file set differs from protected projection")
        for item in expected:
            if item not in changed:
                continue
            from_pr = unpack_content(api("repos/" + REPO + "/contents/" + item +
                                         "?ref=" + head_sha))
            require(from_pr == expected[item],
                    "first-intake index/landscape differs from protected projection")


def eligible_existing_record_prs(selected):
    """Skip first-intake proposals, never blocking verified existing-record updates.

    A signed first Release may generate a PR, but merging its index/landscape
    changes is not an automated operation. Check protected main, not PR code.
    Fail closed if a protected index and record disagree.
    """
    index = json.loads(Path("index.json").read_text(encoding="utf-8"))
    names = index.get("extensions") if type(index) is dict else None
    require(index.get("schemaVersion") == 2 and type(names) is list
            and all(type(n) is str for n in names)
            and names == sorted(set(names)),
            "protected Catalog index missing or inconsistent")
    eligible = []
    for pr in selected:
        branch = (pr.get("head") or {}).get("ref", "")
        match = BRANCH.fullmatch(branch)
        require(match is not None, "unknown automated Catalog PR branch")
        name = match.group(1)
        exists = (Path("extensions") / (name + ".json")).is_file()
        indexed = name in names
        require(exists == indexed,
                "protected Catalog index and current record disagree")
        if exists:
            eligible.append(pr)
    return eligible


def perform(config_path, dry_run=False):
    require(os.environ.get("GITHUB_REPOSITORY") == REPO
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") in (
                "workflow_run", "schedule", "workflow_dispatch"),
            "untrusted Catalog controller event/branch")
    require(type(os.environ.get("GH_TOKEN")) is str
            and len(os.environ["GH_TOKEN"]) > 10
            and os.environ.get("PGEXTWIN_CATALOG_AUTOMERGE_ENABLED") == "true",
            "dedicated merge App token or repository opt-in missing")
    read_token = os.environ.get("GH_READ_TOKEN")
    local = json.loads(Path(config_path).read_text(encoding="utf-8"))
    central = unpack_content(api(
        "repos/" + CENTRAL + "/contents/metadata/manual-release-downstream.json?ref=main"))
    verify_policy(local, central)
    check_app_scope()
    before = api("repos/" + REPO + "/branches/main")
    require(before.get("name") == "main" and before.get("protected") is True
            and SHA.fullmatch((before.get("commit") or {}).get("sha", "")),
            "Catalog main is not protected")
    main_sha = before["commit"]["sha"]
    require(os.environ.get("GITHUB_SHA") == main_sha,
            "trusted workflow/main changed or stale since invocation")
    pulls = api("repos/" + REPO + "/pulls?state=open&base=main&per_page=100")
    require(type(pulls) is list and len(pulls) < 100, "open Catalog PR inventory incomplete")
    selected = [pr for pr in pulls
                if (pr.get("head") or {}).get("ref", "").startswith("auto-catalog/")]
    seen = set()
    for pr in selected:
        branch = (pr.get("head") or {}).get("ref")
        require(type(branch) is str and BRANCH.fullmatch(branch)
                and BRANCH.fullmatch(branch).group(1) in INTAKE_ALLOWED
                and branch not in seen, "duplicate or unknown Catalog automation PR")
        seen.add(branch)
    if not selected:
        print("CATALOG_AUTOMERGE_NO_OP")
        return
    eligible = eligible_existing_record_prs(selected)
    if not eligible:
        print("CATALOG_AUTOMERGE_FIRST_RELEASE_EXCLUDED; NO_MERGE")
        return
    # Never let an early first-intake PR block a subsequent eligible update.
    # One immutable existing-record PR per genuine event; no index mutation.
    pr = min(eligible, key=lambda row: row.get("number", 0))
    number = pr["number"]
    files = api("repos/" + REPO + "/pulls/" + str(number) + "/files?per_page=100")
    commits = api("repos/" + REPO + "/pulls/" + str(number) + "/commits?per_page=100")
    match = BRANCH.fullmatch((pr.get("head") or {}).get("ref", ""))
    require(match is not None, "unknown Catalog automation branch")
    # A second fail-closed gate immediately before any privileged merge.
    require((Path("extensions") / (match.group(1) + ".json")).is_file(),
            "first Catalog Release auto-merge forbidden before PR inspection")
    number, sha, branch, name, tag = inspect_pr(
        pr, files, commits, proposer_login=local["expectedProposerLogin"],
        proposer_id=local["expectedProposerBotId"], initial=False)
    runs = api("repos/" + REPO +
               "/actions/workflows/validate.yml/runs?per_page=100&branch=" + branch)
    validate_run(runs.get("workflow_runs"), sha, branch)
    check_runs = api("repos/" + REPO + "/commits/" + sha + "/check-runs?per_page=100")
    validate_checks(check_runs, sha)
    verify_record(name, tag, sha, read_token=read_token, files=files)
    latest = api("repos/" + REPO + "/pulls/" + str(number))
    require(latest.get("state") == "open" and latest.get("draft") is False
            and (latest.get("head") or {}).get("sha") == sha
            and (latest.get("base") or {}).get("sha") == main_sha
            and latest.get("mergeable") is True
            and latest.get("mergeable_state") == "clean",
            "PR changed, conflicted, or failed protected required checks")
    branch_now = api("repos/" + REPO + "/branches/main")
    require(branch_now.get("protected") is True
            and (branch_now.get("commit") or {}).get("sha") == main_sha,
            "Catalog main advanced before merge")
    if dry_run:
        print("VERIFIED_SIGNED_CATALOG_AUTOMERGE_DRY_RUN", name, tag, number)
        return
    result = json.loads(gh("api", "-X", "PUT", "repos/" + REPO +
                          "/pulls/" + str(number) + "/merge",
                          "-f", "sha=" + sha, "-f", "merge_method=squash"))
    require(result.get("merged") is True, "GitHub protected squash merge denied")
    print("VERIFIED_SIGNED_CATALOG_AUTOMERGE_COMPLETED", name, tag, number)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/verified-release-auto-merge.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--probe-app-output",
                        help="GET-only scoped App proof; always revoke, never merge")
    args = parser.parse_args()
    try:
        if args.probe_app_output:
            require(not args.dry_run, "do not combine App proof and merge modes")
            probe_app(args.probe_app_output)
        else:
            perform(args.config, args.dry_run)
        return 0
    except (AutoMergeDenied, OSError, ValueError, TypeError, KeyError, IndexError) as error:
        print("CATALOG AUTOMERGE DENIED: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
