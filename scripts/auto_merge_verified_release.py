#!/usr/bin/env python3
"""Step 22: fail-closed, scoped Catalog auto-merge after independent signed Release verification.

Runs only from trusted catalog/main, never checks out or executes a PR branch,
and requires BOTH repository-level and live central opt-ins. Missing evidence
blocks publication. An App installation token must be passed through GH_TOKEN.
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

REPO = "pgextwin/catalog"
EXT = "plpgsql_check"
PATH = "extensions/plpgsql_check.json"
BRANCH = re.compile(r"^auto-catalog/plpgsql_check-(v[0-9]+\.[0-9]+\.[0-9]+-windows\.[1-9][0-9]*)$")
SHA = re.compile(r"^[0-9a-f]{40}$")


class AutoMergeDenied(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AutoMergeDenied(message)


def gh(*args):
    cmd = subprocess.run(("gh",) + args, text=True, capture_output=True)
    if cmd.returncode:
        raise AutoMergeDenied("GitHub request denied: " + " ".join(args[:3]) +
                              " " + cmd.stderr[:250])
    return cmd.stdout


def api(path):
    return json.loads(gh("api", path))


def unpack_content(raw):
    require(isinstance(raw, dict) and raw.get("encoding") == "base64"
            and isinstance(raw.get("content"), str), "source content unavailable")
    return json.loads(base64.b64decode(raw["content"], validate=False).decode("utf-8"))


def verify_policy(local, central):
    required = {"schemaVersion", "enabled", "extension", "recordPath",
                "requiredWorkflow", "expectedRepository",
                "centralPolicyRepository", "notes"}
    require(type(local) is dict and set(local) == required and
            local.get("schemaVersion") == 1 and local.get("enabled") is True,
            "local Catalog automatic merge is not enabled")
    require(local["extension"] == EXT and local["recordPath"] == PATH and
            local["requiredWorkflow"] == "validate.yml" and
            local["expectedRepository"] == REPO and
            local["centralPolicyRepository"] == "pgextwin/build",
            "unsupported repository, record or workflow scope")
    require(type(central) is dict and central.get("schemaVersion") == 1 and
            central.get("mode") == "UNATTENDED" and
            central.get("defaultAction") == "DENY" and
            central.get("pilotRepository") == "pgextwin/plpgsql_check" and
            central.get("requiredMajorVersions") == [15, 16, 17, 18],
            "live central policy does not authorize unattended pilot")
    controls = central.get("controls")
    require(type(controls) is dict and controls.get("automaticCatalogMerge") is True
            and controls.get("automaticFormalRelease") is True
            and controls.get("requireBuildProvenance") is True
            and controls.get("requireSbomAttestation") is True
            and controls.get("requireDedicatedMergeApp") is True
            and controls.get("quarantineOnAmbiguity") is True,
            "live central policy lacks the required Catalog safeguards")


def inspect_pr(pr, files, commits):
    require(type(pr) is dict and pr.get("state") == "open" and pr.get("draft") is False,
            "PR not open and reviewable")
    number = pr.get("number")
    require(type(number) is int and number > 0, "invalid PR number")
    head = pr.get("head") or {}
    m = BRANCH.fullmatch(head.get("ref", ""))
    require(m is not None and SHA.fullmatch(head.get("sha", "")),
            "PR branch or head SHA violates immutable automation pattern")
    require((pr.get("user") or {}).get("login") == "github-actions[bot]"
            and (pr.get("base") or {}).get("ref") == "main"
            and (head.get("repo") or {}).get("full_name") == REPO
            and pr.get("commits") == 1,
            "PR author, base, repository or commit count is not trusted")
    require(isinstance(files, list) and len(files) == 1
            and files[0].get("filename") == PATH
            and files[0].get("status") == "modified",
            "PR may only modify the plpgsql_check Catalog record")
    require(isinstance(commits, list) and len(commits) == 1
            and (commits[0].get("commit") or {}).get("message", "").startswith(
                "catalog: propose plpgsql_check " + m.group(1)),
            "automation commit is not the expected generated Catalog record")
    return number, head["sha"], head["ref"], m.group(1)


def validate_run(runs, sha, branch):
    require(type(runs) is list and len(runs) < 100, "workflow list inaccessible/truncated")
    matches = [r for r in runs if r.get("head_sha") == sha and
               r.get("head_branch") == branch and
               r.get("event") in {"workflow_dispatch", "pull_request"}]
    require(bool(matches), "no exact-HEAD independent Catalog validation")
    # Latest run is authoritative; never cherry-pick a historical success.
    latest = max(matches, key=lambda r: (r.get("created_at", ""), r.get("id", 0)))
    require(latest.get("status") == "completed" and
            latest.get("conclusion") == "success",
            "current HEAD validation not complete/successful")


def verify_record(tag, head_sha):
    # Execute only scripts from trusted main, never PR-contributed code.
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "verified.json"
        output.write_bytes(Path(PATH).read_bytes())
        cmd = subprocess.run((sys.executable, "scripts/propose_verified_release.py",
                              "--extension", EXT, "--release-tag", tag,
                              "--output", str(output)),
                             text=True, capture_output=True)
        require(cmd.returncode == 0, "independent signed Release verification failed: " +
                cmd.stderr[:300])
        verified = json.loads(output.read_text(encoding="utf-8"))
    current = json.loads(Path(PATH).read_text(encoding="utf-8"))
    require(verified != current, "stale Catalog PR or no-op")
    untrusted = unpack_content(api(
        "repos/" + REPO + "/contents/" + PATH + "?ref=" + head_sha))
    require(verified == untrusted,
            "candidate record differs from independently verified public Release")


def perform(config_path, dry_run=False):
    require(os.environ.get("GITHUB_REPOSITORY") == REPO and
            os.environ.get("GITHUB_REF") == "refs/heads/main",
            "merge controller must run from trusted Catalog main")
    require(os.environ.get("GH_TOKEN") and
            os.environ.get("PGEXTWIN_CATALOG_AUTOMERGE_ENABLED") == "true",
            "App token and explicit repository variable required")
    local = json.loads(Path(config_path).read_text(encoding="utf-8"))
    central = unpack_content(api(
        "repos/pgextwin/build/contents/metadata/unattended-publication.json?ref=main"))
    verify_policy(local, central)
    pulls = api("repos/" + REPO + "/pulls?state=open&per_page=100")
    require(type(pulls) is list and len(pulls) < 100,
            "open PR list inaccessible or truncated")
    selected = [pr for pr in pulls if (pr.get("head") or {}).get("ref", "").startswith(
        "auto-catalog/")]
    require(len(selected) <= 1, "multiple automation Catalog PRs: quarantine")
    if not selected:
        print("CATALOG_AUTOMERGE_NO_OP")
        return
    pr = selected[0]
    number = pr.get("number")
    files = api("repos/" + REPO + "/pulls/" + str(number) + "/files?per_page=100")
    commits = api("repos/" + REPO + "/pulls/" + str(number) + "/commits?per_page=100")
    number, sha, branch, tag = inspect_pr(pr, files, commits)
    runs = api("repos/" + REPO +
               "/actions/workflows/validate.yml/runs?per_page=100&branch=" + branch)
    require(type(runs) is dict, "invalid workflow run listing")
    validate_run(runs.get("workflow_runs"), sha, branch)
    verify_record(tag, sha)
    # Recheck the branch head immediately before a mutation.
    current_pr = api("repos/" + REPO + "/pulls/" + str(number))
    require(current_pr.get("state") == "open" and
            (current_pr.get("head") or {}).get("sha") == sha,
            "PR head moved during verification")
    if dry_run:
        print("CATALOG_AUTOMERGE_VERIFIED_DRY_RUN PR #" + str(number))
        return
    response = json.loads(gh("api", "-X", "PUT", "repos/" + REPO +
                             "/pulls/" + str(number) + "/merge",
                             "-f", "sha=" + sha, "-f", "merge_method=squash"))
    require(response.get("merged") is True, "merge not confirmed by GitHub")
    print("CATALOG_AUTOMERGE_COMPLETED PR #" + str(number))


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
