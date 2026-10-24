#!/usr/bin/env python3
"""Independently bind a public automatic signed Release to real GitHub Run GETs.

A Release-body marker is only an UNTRUSTED locator. Full original signed ZIP,
SHA256, SPDX, Grype and both real Sigstore verifications are performed by the
existing Catalog verifier; this module additionally authenticates the distinct
completed source main/push and central scheduled Publisher, with the dedicated
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
PUBLISHER=".github/workflows/publisher-candidate-intake.yml"
PUBLISH_JOB="Isolated Publisher App signed formal Release (create only)"
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
    require(type(obj) is dict and set(obj)==FIELDS and
            type(obj.get("schemaVersion")) is int and obj["schemaVersion"]==1
            and obj.get("authorizationMode")=="automatic-schedule"
            and type(obj.get("repository")) is str and REPO.fullmatch(obj["repository"])
            and type(obj.get("releaseTag")) is str and TAG.fullmatch(obj["releaseTag"])
            and type(obj.get("packagingCommit")) is str and SHA.fullmatch(obj["packagingCommit"])
            and type(obj.get("sourceRunId")) is int and obj["sourceRunId"]>0
            and type(obj.get("sourceRunAttempt")) is int and obj["sourceRunAttempt"]==1
            and obj.get("sourceWorkflow")==SOURCE
            and obj.get("publisherRepository")=="pgextwin/build"
            and type(obj.get("publisherRunId")) is int and obj["publisherRunId"]>0
            and obj["publisherRunId"]!=obj["sourceRunId"]
            and type(obj.get("publisherRunAttempt")) is int and obj["publisherRunAttempt"]==1
            and type(obj.get("publisherMainSha")) is str and SHA.fullmatch(obj["publisherMainSha"])
            and obj.get("publisherWorkflow")==PUBLISHER
            and type(obj.get("publisherAppId")) is int and obj["publisherAppId"]==5451798
            and obj.get("approvalProvenance")=="INDEPENDENT_LIVE_SCHEDULE_AND_SIGNED_SOURCE",
            "unknown automatic source/Publisher origin")
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
    require(type(source) is dict and type(source.get("id")) is int and
            source["id"]==source_run_id and
            type(source.get("run_attempt")) is int and source["run_attempt"]==1 and
            source.get("event")=="push" and source.get("path")==SOURCE and
            source.get("head_sha")==sha and source.get("head_branch")=="main" and
            source.get("status")=="completed" and source.get("conclusion")=="success" and
            (source.get("repository") or {}).get("full_name")==repository,
            "original signed main/push Run is not completed successfully")
    pub_id=marker["publisherRunId"]
    schedule=api("repos/pgextwin/build/actions/runs/"+str(pub_id))
    require(type(schedule) is dict and type(schedule.get("id")) is int and
            schedule["id"]==pub_id and type(schedule.get("run_attempt")) is int and
            schedule["run_attempt"]==1 and schedule.get("event")=="schedule" and
            schedule.get("path")==PUBLISHER and
            schedule.get("head_sha")==marker["publisherMainSha"] and
            schedule.get("head_branch")=="main" and
            schedule.get("status")=="completed" and
            schedule.get("conclusion")=="success" and
            (schedule.get("repository") or {}).get("full_name")=="pgextwin/build",
            "genuine scheduled central Publisher did not succeed")
    jobs=api("repos/pgextwin/build/actions/runs/"+str(pub_id)+"/attempts/1/jobs?per_page=100")
    require(type(jobs) is dict and type(jobs.get("total_count")) is int and
            type(jobs.get("jobs")) is list and
            jobs["total_count"]==len(jobs["jobs"]) and
            0<len(jobs["jobs"])<100,
            "Publisher job inventory incomplete or paginated")
    publishers=[job for job in jobs["jobs"] if
                type(job) is dict and type(job.get("name")) is str and
                (job["name"]==PUBLISH_JOB or
                 job["name"].startswith(PUBLISH_JOB+" ("))]
    # GitHub matrix may contain many distinct extension jobs; require the
    # exact requested extension in this success job's matrix display suffix.
    extension=repository.split("/")[-1]
    matching=[job for job in publishers
              if job["name"].startswith(PUBLISH_JOB+" (") and
              re.search(r"\b"+re.escape(extension)+r"\b",job["name"])]
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
        "status":"INDEPENDENT_AUTOMATIC_SIGNED_PUBLISHER_LIVE_MATCH",
        "repository":repository,"releaseTag":tag,"sourceRunId":source_run_id,
        "publisherRunId":pub_id,"publisherAppId":5451798,
        "sigstoreReleaseBytesMustBeVerifiedSeparately":True,
    }
