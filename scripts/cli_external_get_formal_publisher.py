#!/usr/bin/env python3
"""Fail-closed independent CLI publisher authorization; never invokes a write API."""
import argparse
import json
import re
import sys
from pathlib import Path

FIXED = {
    "schemaVersion": "pgextwin-cli-external-get-formal-publisher/v1",
    "environmentName": "cli-external-get-publisher",
    "ownerLogin": "ShutenOishi", "ownerId": 27071164,
    "repository": "pgextwin/catalog", "operation": "ORIGINAL_PROVIDER_GET_ONLY",
    "extension": "pg_trickle", "postgresqlMajor": 18,
    "mirrorAuthorized": False, "redistributionAuthorized": False,
}
EXPECTED = set(FIXED) | {"publishAuthorized", "approvedVersion", "environmentId"}
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class Denied(Exception):
    pass


def require(condition, explanation):
    if not condition:
        raise Denied(explanation)


def no_duplicates(pairs):
    value = {}
    for name, item in pairs:
        require(name not in value, "duplicate JSON key")
        value[name] = item
    return value


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"),
                      object_pairs_hook=no_duplicates)


def eligible(policy, version):
    require(type(policy) is dict and set(policy) == EXPECTED,
            "unexpected publisher policy fields")
    for key, expected in FIXED.items():
        require(type(policy[key]) is type(expected) and policy[key] == expected,
                "publisher scope mismatch: " + key)
    require(type(policy["publishAuthorized"]) is bool, "invalid approval flag")
    require(policy["environmentId"] is None or
            (type(policy["environmentId"]) is int and policy["environmentId"] > 0),
            "invalid pinned Environment ID")
    require(policy["approvedVersion"] is None or
            (type(policy["approvedVersion"]) is str and
             VERSION.fullmatch(policy["approvedVersion"])),
            "invalid approved version")
    require(type(version) is str and VERSION.fullmatch(version),
            "invalid CLI version")
    if not policy["publishAuthorized"]:
        require(policy["approvedVersion"] is None and policy["environmentId"] is None,
                "disabled publisher cannot retain approval fields")
        return False
    require(type(policy["environmentId"]) is int and policy["environmentId"] > 0,
            "an actual reviewed Environment ID must be pinned")
    require(version == policy["approvedVersion"] and
            tuple(map(int, version.split("."))) > (0, 3, 6),
            "CLI version is not separately authorized")
    return True


def approve_same_run(policy, version, run, approvals, run_id):
    require(eligible(policy, version), "formal publisher remains disabled")
    require(type(run_id) is int and run_id > 0, "invalid current Run ID")
    require(type(run) is dict and run.get("id") == run_id and
            run.get("run_attempt") == 1 and
            run.get("event") == "workflow_run" and
            run.get("path") == ".github/workflows/cli-release.yml" and
            (run.get("repository") or {}).get("full_name") == policy["repository"] and
            run.get("head_branch") == "main" and
            run.get("status") == "in_progress",
            "current original CLI Release Run identity mismatch")
    require(type(approvals) is list, "missing approval history")
    for review in approvals:
        if not isinstance(review, dict):
            continue
        user = review.get("user") or {}
        environments = review.get("environments") or []
        if (review.get("state") == "approved" and
            user.get("login") == policy["ownerLogin"] and
            user.get("id") == policy["ownerId"] and
            isinstance(environments, list) and
            any(type(env) is dict and
                env.get("name") == policy["environmentName"] and
                env.get("id") == policy["environmentId"]
                for env in environments)):
            return True
    raise Denied("owner did not approve the pinned Environment in this Run")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("policy", "approval"))
    parser.add_argument("--policy", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--run")
    parser.add_argument("--approvals")
    parser.add_argument("--run-id", type=int)
    args = parser.parse_args(argv)
    try:
        policy = read_json(args.policy)
        if not eligible(policy, args.version):
            print("CLI_FORMAL_PUBLISHER=DENY_NOT_ARMED")
            return 4
        if args.mode == "approval":
            require(args.run is not None and args.approvals is not None and
                    args.run_id is not None, "missing exact Run proof")
            approve_same_run(policy, args.version, read_json(args.run),
                             read_json(args.approvals), args.run_id)
            print("CLI_FORMAL_PUBLISHER=APPROVED_SAME_RUN_ENVIRONMENT")
        else:
            print("CLI_FORMAL_PUBLISHER=POLICY_ELIGIBLE_ENV_REVIEW_STILL_REQUIRED")
        return 0
    except (Denied, ValueError, KeyError, TypeError, OSError) as error:
        print("CLI_FORMAL_PUBLISHER=DENY " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
