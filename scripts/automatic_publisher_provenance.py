#!/usr/bin/env python3
"""Independently bind a public automatic signed Release to real GitHub Run GETs.

A Release-body marker is only an UNTRUSTED locator. Full original signed ZIP,
SHA256, SPDX, Grype and both real Sigstore verifications are performed by the
existing Catalog verifier; this module additionally authenticates the distinct
completed source main/push and central Publisher, with the dedicated
App as Release author. Manual operator Releases use their separate unchanged
check. Offline/mock fixtures are NEVER public Release acceptance.
"""
from __future__ import annotations
from datetime import datetime
import json
import re

PREFIX="<!-- PGEXTWIN_AUTOMATIC_SIGNED_PROVENANCE_V1="
SUFFIX=" -->"
SHA=re.compile(r"^[0-9a-f]{40}$")
REPO=re.compile(r"^pgextwin/[a-z][a-z0-9_]*$")
TAG=re.compile(r"^v[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]{8})?-windows\.[1-9][0-9]*$")
FIELDS={
    "schemaVersion","authorizationMode","repository","releaseTag",
    "packagingCommit","sourceRunId","sourceRunAttempt",
    "sourceWorkflow","publisherRepository","publisherRunId",
    "publisherRunAttempt","publisherMainSha","publisherWorkflow",
    "publisherAppId","approvalProvenance",
}
SOURCE=".github/workflows/update-watch.yml"
OWNER_SOURCE=".github/workflows/chat-signed-main.yml"
OWNER_KIND="OWNER_ISSUE_COMMENT_MAIN_SIGNING"
PUBLISHER=".github/workflows/publisher-candidate-intake.yml"
PUBLISH_JOB="Isolated Publisher App signed formal Release (create only)"
OWNER_PUBLISH_JOB="Isolated original owner signed-main formal Publisher (create only)"
OWNER_ADMIT_JOB="Authenticate owner formal-source request and reverify original (DENY)"
OWNER_LOGIN="ShutenOishi"
OWNER_ID=27071164
# Protected, source-specific sign-main issue binding. No generic owner-comments.
# Expansion requires a reviewed protected policy change and hostile tests.
OWNER_SIGNING_ISSUES={
    "pgextwin/plpgsql_check":78,
    "pgextwin/set_user":60,
    "pgextwin/pg_ivm":67,
    "pgextwin/orafce":94,
    "pgextwin/pg_hint_plan":69,
}
ORIGINS={
    "automatic-schedule": ("schedule", "INDEPENDENT_LIVE_SCHEDULE_AND_SIGNED_SOURCE"),
    "owner-dispatch": ("workflow_dispatch", "INDEPENDENT_LIVE_OWNER_DISPATCH_AND_SIGNED_SOURCE"),
    "owner-issue-comment": ("issue_comment", "INDEPENDENT_LIVE_OWNER_COMMENT_AND_SIGNED_SOURCE"),
    "owner-signed-main-issue-comment": ("issue_comment",
                                        "INDEPENDENT_LIVE_OWNER_MAIN_SIGNING_AND_PUBLISH_REQUEST"),
}
class Denied(ValueError): pass

def require(ok,reason):
    if not ok: raise Denied(reason)

def parse(body):
    require(type(body) is str and len(body)<1000000,"missing/oversized public Release notes")
    lines=[line for line in body.splitlines() if line.startswith(PREFIX)]
    require(len(lines)==1 and lines[0].endswith(SUFFIX),
            "missing/duplicate/malformed automatic Publisher locator")
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,"duplicate automatic locator JSON key")
            result[key]=value
        return result
    try: obj=json.loads(lines[0][len(PREFIX):-len(SUFFIX)],object_pairs_hook=unique)
    except (ValueError,TypeError) as exc:
        raise Denied("malformed automatic locator") from exc
    mode=obj.get("authorizationMode") if type(obj) is dict else None
    extra=({"requestCommentId","sourceSigningCommentId","sourceKind"}
           if mode=="owner-signed-main-issue-comment" else
           {"requestCommentId"} if mode=="owner-issue-comment" else set())
    require(type(obj) is dict and set(obj)==FIELDS|extra and
            type(obj.get("schemaVersion")) is int and obj["schemaVersion"]==1
            and type(obj.get("authorizationMode")) is str
            and obj["authorizationMode"] in ORIGINS
            and type(obj.get("repository")) is str and REPO.fullmatch(obj["repository"])
            and type(obj.get("releaseTag")) is str and TAG.fullmatch(obj["releaseTag"])
            and type(obj.get("packagingCommit")) is str and SHA.fullmatch(obj["packagingCommit"])
            and type(obj.get("sourceRunId")) is int and obj["sourceRunId"]>0
            and type(obj.get("sourceRunAttempt")) is int and obj["sourceRunAttempt"]==1
            and obj.get("sourceWorkflow")==(
                OWNER_SOURCE if mode=="owner-signed-main-issue-comment" else SOURCE)
            and obj.get("publisherRepository")=="pgextwin/build"
            and type(obj.get("publisherRunId")) is int and obj["publisherRunId"]>0
            and obj["publisherRunId"]!=obj["sourceRunId"]
            and type(obj.get("publisherRunAttempt")) is int and obj["publisherRunAttempt"]==1
            and type(obj.get("publisherMainSha")) is str and SHA.fullmatch(obj["publisherMainSha"])
            and obj.get("publisherWorkflow")==PUBLISHER
            and type(obj.get("publisherAppId")) is int and obj["publisherAppId"]==5451798
            and obj.get("approvalProvenance")==ORIGINS[obj["authorizationMode"]][1],
            "unknown automatic source/Publisher origin")
    if mode in ("owner-issue-comment","owner-signed-main-issue-comment"):
        require(type(obj.get("requestCommentId")) is int and obj["requestCommentId"]>0,
                "missing exact owner comment ID")
    if mode=="owner-signed-main-issue-comment":
        require(obj.get("sourceKind")==OWNER_KIND
                and type(obj.get("sourceSigningCommentId")) is int
                and obj["sourceSigningCommentId"]>0
                and obj["sourceSigningCommentId"]!=obj["requestCommentId"],
                "missing distinct original owner signing identity")
    return obj

def timestamp(value):
    require(type(value) is str and value.endswith("Z"),
            "GitHub schedule/Release timestamp lacks UTC Z")
    try: date=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as exc:raise Denied("invalid timestamp") from exc
    require(date.tzinfo is not None,"untrusted timezone")
    return date

def verify(*,release,repository,tag,sha,source_run_id,marker,api):
    """Real verifier MUST pass its authenticated REST GET function as api."""
    require(type(release) is dict and type(repository) is str and
            REPO.fullmatch(repository) and type(tag) is str and TAG.fullmatch(tag)
            and type(sha) is str and SHA.fullmatch(sha)
            and type(source_run_id) is int and source_run_id>0
            and type(marker) is dict and marker==parse(release.get("body")),
            "release marker was substituted or malformed")
    require(marker["repository"]==repository and
            marker["releaseTag"]==tag and marker["packagingCommit"]==sha and
            marker["sourceRunId"]==source_run_id and
            release.get("target_commitish")==sha and
            release.get("tag_name")==tag and release.get("draft") is False and
            release.get("prerelease") is False and
            type(release.get("author")) is dict and
            release["author"].get("login")=="pgextwin-publisher[bot]" and
            release["author"].get("type")=="Bot",
            "formal Release not owned by independently scoped Publisher App")
    source=api("repos/"+repository+"/actions/runs/"+str(source_run_id))
    owner_signed=marker["authorizationMode"]=="owner-signed-main-issue-comment"
    require(type(source) is dict and type(source.get("id")) is int and
            source["id"]==source_run_id and
            type(source.get("run_attempt")) is int and source["run_attempt"]==1 and
            source.get("event")==("issue_comment" if owner_signed else "push") and
            source.get("path")==(OWNER_SOURCE if owner_signed else SOURCE) and
            source.get("head_sha")==sha and source.get("head_branch")=="main" and
            source.get("status")=="completed" and source.get("conclusion")=="success" and
            (source.get("repository") or {}).get("full_name")==repository,
            "original signed main/push Run is not completed successfully")
    if owner_signed:
        # Source-specific, protected repository/issue binding. The exact
        # GitHub owner actor and original immutable comment are checked below.
        issue=OWNER_SIGNING_ISSUES.get(repository)
        require(type(issue) is int and issue>0
                and source.get("display_title")==
                    f"Chat-main-sign-comment-{marker['sourceSigningCommentId']}",
                "owner signing Run not the registered protected issue-bound source")
        for field in ("actor","triggering_actor"):
            person=source.get(field)
            require(type(person) is dict and person.get("login")==OWNER_LOGIN
                    and type(person.get("id")) is int and person["id"]==OWNER_ID
                    and person.get("type")=="User",
                    "real original owner signing actor mismatch")
        signed=api("repos/"+repository+"/issues/comments/"+
                   str(marker["sourceSigningCommentId"]))
        require(type(signed) is dict
                and signed.get("id")==marker["sourceSigningCommentId"]
                and type(signed.get("user")) is dict
                and signed["user"].get("login")==OWNER_LOGIN
                and type(signed["user"].get("id")) is int
                and signed["user"]["id"]==OWNER_ID
                and signed["user"].get("type")=="User"
                and signed.get("body")=="/pgextwin sign-main"
                and signed.get("issue_url")==
                    f"https://api.github.com/repos/{repository}/issues/{issue}"
                and signed.get("created_at")==signed.get("updated_at")
                and timestamp(signed.get("created_at"))<=timestamp(source.get("created_at")),
                "original owner signer command edited, moved or faked")
    pub_id=marker["publisherRunId"]
    schedule=api("repos/pgextwin/build/actions/runs/"+str(pub_id))
    expected_event=ORIGINS[marker["authorizationMode"]][0]
    require(type(schedule) is dict and type(schedule.get("id")) is int and
            schedule["id"]==pub_id and type(schedule.get("run_attempt")) is int and
            schedule["run_attempt"]==1 and schedule.get("event")==expected_event and
            schedule.get("path")==PUBLISHER and
            schedule.get("head_sha")==marker["publisherMainSha"] and
            schedule.get("head_branch")=="main" and
            schedule.get("status")=="completed" and
            schedule.get("conclusion")=="success" and
            (schedule.get("repository") or {}).get("full_name")=="pgextwin/build",
            "genuine central Publisher did not succeed")
    if expected_event in ("workflow_dispatch","issue_comment"):
        for field in ("actor", "triggering_actor"):
            person=schedule.get(field)
            require(type(person) is dict and person.get("login")==OWNER_LOGIN
                    and type(person.get("id")) is int and person["id"]==OWNER_ID
                    and person.get("type")=="User",
                    "owner dispatch actor identity not authenticated")
    if expected_event=="issue_comment":
        cid=marker["requestCommentId"]
        require(schedule.get("display_title")==f"Publisher-issue_comment-comment-{cid}",
                "Publisher Run not linked to owner comment")
        comment=api("repos/pgextwin/build/issues/comments/"+str(cid))
        require(type(comment) is dict and comment.get("id")==cid
                and type(comment.get("user")) is dict
                and comment["user"].get("login")==OWNER_LOGIN
                and type(comment["user"].get("id")) is int
                and comment["user"]["id"]==OWNER_ID
                and comment["user"].get("type")=="User"
                and comment.get("body")==(
                    f"/pgextwin publish-owner-source {repository} {source_run_id}"
                    if owner_signed else f"/pgextwin publish {repository}")
                and comment.get("issue_url")=="https://api.github.com/repos/pgextwin/build/issues/311"
                and comment.get("created_at")==comment.get("updated_at"),
                "owner issue comment mutated or mismatched")
        require(timestamp(source.get("created_at"))<=timestamp(comment["created_at"])
                <=timestamp(schedule.get("created_at")),
                "comment timestamp outside source/Publisher interval")
    jobs=api("repos/pgextwin/build/actions/runs/"+str(pub_id)+"/attempts/1/jobs?per_page=100")
    require(type(jobs) is dict and type(jobs.get("total_count")) is int and
            type(jobs.get("jobs")) is list and
            jobs["total_count"]==len(jobs["jobs"]) and
            0<len(jobs["jobs"])<100,
            "Publisher job inventory incomplete or paginated")
    extension=repository.split("/")[-1]
    exact_job=(OWNER_PUBLISH_JOB if owner_signed else
               PUBLISH_JOB+" ("+extension+")")
    matching=[job for job in jobs["jobs"]
              if type(job) is dict and job.get("name")==exact_job]
    if owner_signed:
        admissions=[job for job in jobs["jobs"]
                    if type(job) is dict and job.get("name")==OWNER_ADMIT_JOB]
        require(len(admissions)==1
                and admissions[0].get("run_id")==pub_id
                and type(admissions[0].get("run_attempt")) is int
                and admissions[0]["run_attempt"]==1
                and admissions[0].get("head_sha")==marker["publisherMainSha"]
                and admissions[0].get("status")=="completed"
                and admissions[0].get("conclusion")=="success",
                "no same-original-Run independent owner signed source admission")
    require(len(matching)==1 and
            type(matching[0].get("run_id")) is int and matching[0]["run_id"]==pub_id and
            type(matching[0].get("run_attempt")) is int and matching[0]["run_attempt"]==1 and
            matching[0].get("head_sha")==marker["publisherMainSha"] and
            matching[0].get("status")=="completed" and
            matching[0].get("conclusion")=="success",
            "no exactly matched successful independent Publisher matrix job")
    # The authenticated successful central schedule is only part of the
    # result: the caller separately verifies each REAL public ZIP's Sigstore.
    source_time=timestamp(source.get("created_at"))
    schedule_time=timestamp(schedule.get("created_at"))
    release_time=timestamp(release.get("published_at"))
    end_time=timestamp(schedule.get("updated_at"))
    require(source_time<=schedule_time<=release_time<=end_time,
            "source/scheduled Publisher/Release timestamps out of order")
    return {
        "status":("INDEPENDENT_OWNER_MAIN_SIGNING_PUBLISHER_LIVE_MATCH"
                  if owner_signed else
                  "INDEPENDENT_OWNER_DISPATCH_SIGNED_PUBLISHER_LIVE_MATCH"
                  if expected_event=="workflow_dispatch" else
                  "INDEPENDENT_OWNER_COMMENT_SIGNED_PUBLISHER_LIVE_MATCH"
                  if expected_event=="issue_comment" else
                  "INDEPENDENT_AUTOMATIC_SIGNED_PUBLISHER_LIVE_MATCH"),
        "repository":repository,"releaseTag":tag,"sourceRunId":source_run_id,
        "publisherRunId":pub_id,"publisherAppId":5451798,
        "sigstoreReleaseBytesMustBeVerifiedSeparately":True,
    }
