#!/usr/bin/env python3
"""Issue #75: fail-closed, fleet-wide merge of independently signed Catalog PRs.

The private Catalog merge App can merge an existing, *fully reverified* record PR
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
    from scripts.verified_release_record import INTAKE_ALLOWED
except ModuleNotFoundError:
    from verified_release_record import INTAKE_ALLOWED

REPO = "pgextwin/catalog"
CENTRAL = "pgextwin/build"
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


def gh(*args):
    result = subprocess.run(("gh",) + args, capture_output=True, text=True)
    require(result.returncode == 0, "authenticated GitHub request denied: " +
            " ".join(args[:3]) + " " + result.stderr[:200])
    return result.stdout


def api(path):
    return json.loads(gh("api", path))


def unpack_content(raw):
    require(type(raw) is dict and raw.get("encoding") == "base64"
            and type(raw.get("content")) is str, "trusted contents unavailable")
    return json.loads(base64.b64decode(raw["content"], validate=True).decode("utf-8"))


def verify_policy(local, central):
    """Both independent protected opt-ins required; never infer from Release tags."""
    local_fields = {
        "schemaVersion", "enabled", "expectedRepository", "centralPolicyRepository",
        "requiredWorkflow", "requiredCheckAppId", "expectedProposerLogin", "expectedProposerBotId", "notes"
    }
    require(type(local) is dict and set(local) == local_fields
            and type(local.get("schemaVersion")) is int
            and local["schemaVersion"] == 2
            and local.get("enabled") is True
            and local.get("expectedRepository") == REPO
            and local.get("centralPolicyRepository") == CENTRAL
            and local.get("requiredWorkflow") == "validate.yml"
            and type(local.get("requiredCheckAppId")) is int
            and local["requiredCheckAppId"] == 15368
            and local.get("expectedProposerLogin") == "pgextwin-catalog-proposer[bot]"
            and type(local.get("expectedProposerBotId")) is int
            and local["expectedProposerBotId"] == 341259304,
            "Catalog-wide signed merge policy disabled or mismatched")
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


def inspect_pr(pr, files, commits, *, proposer_login, proposer_id):
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
    require(type(files) is list and len(files) == 1
            and files[0].get("filename") == path
            and files[0].get("status") == "modified", "Catalog PR is not record-only")
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


def verify_record(name, tag, head_sha, *, read_token):
    """Fresh public-byte/Sigstore/GitHub-source check with a READ-ONLY token."""
    require(name in INTAKE_ALLOWED and SHA.fullmatch(head_sha)
            and type(read_token) is str and len(read_token) > 10,
            "unsigned verifier input or read token missing")
    path = "extensions/" + name + ".json"
    require(Path(path).is_file(), "no trusted existing Catalog record; initial import DENY")
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        (temp / "extensions").mkdir()
        candidate = temp / path
        candidate.write_bytes(Path(path).read_bytes())
        env = dict(os.environ, GH_TOKEN=read_token)
        run = subprocess.run(
            (sys.executable, str(ROOT / "scripts" / "verify_signed_fleet_release.py"),
             "--extension", name, "--release-tag", tag, "--record-output", path),
            cwd=temp, env=env, text=True, capture_output=True
        )
        require(run.returncode == 0,
                "fresh signed public Release verification DENY: " + run.stderr[:300])
        verified = json.loads(candidate.read_text(encoding="utf-8"))
    original = json.loads(Path(path).read_text(encoding="utf-8"))
    require(verified != original, "signed Release already in Catalog/no-op")
    proposed = unpack_content(api("repos/" + REPO + "/contents/" + path +
                                  "?ref=" + head_sha))
    require(proposed == verified, "PR record differs from independently signed public bytes")


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
    # One immutable, checked PR per invocation; subsequent authentic events
    # process the remaining eligible records without bypassing branch protection.
    pr = min(selected, key=lambda row: row.get("number", 0))
    number = pr["number"]
    files = api("repos/" + REPO + "/pulls/" + str(number) + "/files?per_page=100")
    commits = api("repos/" + REPO + "/pulls/" + str(number) + "/commits?per_page=100")
    number, sha, branch, name, tag = inspect_pr(
        pr, files, commits, proposer_login=local["expectedProposerLogin"],
        proposer_id=local["expectedProposerBotId"])
    runs = api("repos/" + REPO +
               "/actions/workflows/validate.yml/runs?per_page=100&branch=" + branch)
    validate_run(runs.get("workflow_runs"), sha, branch)
    check_runs = api("repos/" + REPO + "/commits/" + sha + "/check-runs?per_page=100")
    validate_checks(check_runs, sha)
    verify_record(name, tag, sha, read_token=read_token)
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
    args = parser.parse_args()
    try:
        perform(args.config, args.dry_run)
        return 0
    except (AutoMergeDenied, OSError, ValueError, TypeError, KeyError, IndexError) as error:
        print("CATALOG AUTOMERGE DENIED: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
