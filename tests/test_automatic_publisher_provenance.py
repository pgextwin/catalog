#!/usr/bin/env python3
"""Offline DENY fixtures for independent public automated signed Release origin.

Synthetic Run JSON and unsigned ZIPs here are NEVER genuine GitHub/Sigstore
evidence. Existing Catalog verifier must still rehash all public assets and
verify every ZIP's real signer-workflow and SPDX predicate.
"""
from copy import deepcopy
from datetime import datetime,timezone,timedelta
import json
from pathlib import Path
import tempfile
import unittest

from scripts import automatic_publisher_provenance as p
from scripts import verify_signed_fleet_release as release
from tests.test_verify_signed_fleet_release import fixture as signed_fixture

REPO="pgextwin/pg_hint_plan"
TAG="v1.5.3-windows.2"
SHA="c"*40
PUB_SHA="d"*40
SRC_RUN=902
PUB_RUN=87319

def marker():
    return {
        "schemaVersion":1,"authorizationMode":"automatic-schedule",
        "repository":REPO,"releaseTag":TAG,"packagingCommit":SHA,
        "sourceRunId":SRC_RUN,"sourceRunAttempt":1,
        "sourceWorkflow":p.SOURCE,
        "publisherRepository":"pgextwin/build","publisherRunId":PUB_RUN,
        "publisherRunAttempt":1,"publisherMainSha":PUB_SHA,
        "publisherWorkflow":p.PUBLISHER,"publisherAppId":5451798,
        "approvalProvenance":"INDEPENDENT_LIVE_SCHEDULE_AND_SIGNED_SOURCE",
    }

def notes(m=None):
    m=marker() if m is None else m
    return "Public Release\n"+p.PREFIX+json.dumps(
        m,sort_keys=True,separators=(",",":"))+p.SUFFIX+"\n"

def events():
    # Real Run timestamps are GitHub REST ISO8601, immutable identity fields
    # are checked again in the actual Catalog environment.
    return {
        "source":{
            "id":SRC_RUN,"run_attempt":1,"event":"push","path":p.SOURCE,
            "head_sha":SHA,"head_branch":"main","status":"completed",
            "conclusion":"success","repository":{"full_name":REPO},
            "created_at":"2026-10-24T08:00:00Z"},
        "publisher":{
            "id":PUB_RUN,"run_attempt":1,"event":"schedule",
            "path":p.PUBLISHER,"head_sha":PUB_SHA,"head_branch":"main",
            "status":"completed","conclusion":"success",
            "repository":{"full_name":"pgextwin/build"},
            "created_at":"2026-10-24T09:00:00Z",
            "updated_at":"2026-10-24T09:10:00Z"},
        "jobs":{
            "total_count":2,
            "jobs":[
                {"name":"Inspect 17/future candidate signed runs; deny unverified Release",
                 "id":1,"run_id":PUB_RUN,"run_attempt":1,"head_sha":PUB_SHA,
                 "status":"completed","conclusion":"success"},
                {"name":p.PUBLISH_JOB+" (pg_hint_plan)",
                 "id":2,"run_id":PUB_RUN,"run_attempt":1,"head_sha":PUB_SHA,
                 "status":"completed","conclusion":"success"},
            ],
        },
        "release":{
            "tag_name":TAG,"target_commitish":SHA,
            "draft":False,"prerelease":False,
            "author":{"login":"pgextwin-publisher[bot]","type":"Bot"},
            "published_at":"2026-10-24T09:05:00Z",
            "body":notes(),
        },
    }

def verify(got):
    endpoints={
        f"repos/{REPO}/actions/runs/{SRC_RUN}":got["source"],
        f"repos/pgextwin/build/actions/runs/{PUB_RUN}":got["publisher"],
        f"repos/pgextwin/build/actions/runs/{PUB_RUN}/attempts/1/jobs?per_page=100":got["jobs"],
    }
    called=[]
    def api(path):
        called.append(path)
        if path not in endpoints:raise AssertionError("unexpected GET "+path)
        return endpoints[path]
    result=p.verify(release=got["release"],repository=REPO,tag=TAG,
                    sha=SHA,source_run_id=SRC_RUN,
                    marker=p.parse(got["release"]["body"]),api=api)
    return result,called

class PublicAutoOrigin(unittest.TestCase):
    def test_distinct_real_run_links_structurally_valid(self):
        result,called=verify(events())
        self.assertEqual(result["status"],
                         "INDEPENDENT_AUTOMATIC_SIGNED_PUBLISHER_LIVE_MATCH")
        self.assertEqual(result["sourceRunId"],SRC_RUN)
        self.assertEqual(result["publisherRunId"],PUB_RUN)
        self.assertEqual(len(called),3)
        self.assertTrue(result["sigstoreReleaseBytesMustBeVerifiedSeparately"])

    def test_duplicate_or_malformed_marker_denied(self):
        value=notes()
        for candidate in (
            "No automatic source marker",
            value+value,
            value.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'),
            value.replace(" -->", " --> and forged text",1),
            value.replace(p.SUFFIX, "-->",1),
            value.replace('"publisherAppId":5451798','"publisherAppId":15368'),
        ):
            with self.subTest(text=candidate[-90:]),self.assertRaises(p.Denied):
                p.parse(candidate)

    def test_forged_author_source_sched_run_job_and_timestamp_rejected(self):
        transforms=[
            lambda x:x["release"]["author"].update(login="github-actions[bot]"),
            lambda x:x["release"]["author"].update(type="User"),
            lambda x:x["release"].update(draft=True),
            lambda x:x["release"].update(target_commitish="e"*40),
            lambda x:x["release"].update(published_at="2026-10-24T09:11:00Z"),
            lambda x:x["source"].update(id=SRC_RUN+1),
            lambda x:x["source"].update(event="workflow_dispatch"),
            lambda x:x["source"].update(path=".github/workflows/promote.yml"),
            lambda x:x["source"].update(run_attempt=2),
            lambda x:x["source"].update(conclusion="failure"),
            lambda x:x["source"].update(head_sha="e"*40),
            lambda x:x["source"].update(created_at="2026-10-24T09:09:00Z"),
            lambda x:x["publisher"].update(event="push"),
            lambda x:x["publisher"].update(path=".github/workflows/validate.yml"),
            lambda x:x["publisher"].update(run_attempt=2),
            lambda x:x["publisher"].update(conclusion="failure"),
            lambda x:x["publisher"].update(head_sha="e"*40),
            lambda x:x["publisher"].update(updated_at="2026-10-24T09:04:00Z"),
            lambda x:x["publisher"].update(created_at="2026-10-24T07:00:00Z"),
            lambda x:x["jobs"].update(total_count=1),
            lambda x:x["jobs"]["jobs"][1].update(name=p.PUBLISH_JOB+" (orafce)"),
            lambda x:x["jobs"]["jobs"][1].update(conclusion="failure"),
            lambda x:x["jobs"]["jobs"][1].update(run_id=999),
            lambda x:x["jobs"]["jobs"][1].update(run_attempt=2),
            lambda x:x["jobs"]["jobs"][1].update(head_sha="b"*40),
            lambda x:x["jobs"]["jobs"].append(deepcopy(x["jobs"]["jobs"][1])),
        ]
        for index,mutate in enumerate(transforms):
            with self.subTest(index=index),self.assertRaises(p.Denied):
                item=events()
                mutate(item)
                verify(item)

    def test_push_zip_accepted_only_with_independent_auto_mode(self):
        with tempfile.TemporaryDirectory() as d:
            folder=Path(d)
            signed,manifest,contract,commit=signed_fixture(folder)
            zips=sorted(folder.glob("*.zip"))
            from zipfile import ZipFile
            for file in zips:
                with ZipFile(file) as z:
                    info=json.loads(z.read("PACKAGE-INFO.json"))
                info["workflowRun"]["event"]="push"
                info["workflowRun"]["attempt"]=1
                with ZipFile(file,"w") as z:
                    z.writestr("PACKAGE-INFO.json",json.dumps(info))
            # Refresh checksum and GitHub metadata for unsigned synthetic ZIPs.
            files={p.name:p for p in folder.iterdir() if p.name!="SHA256SUMS.txt"}
            sums={name:release.digest(file) for name,file in files.items()}
            (folder/"SHA256SUMS.txt").write_text(
                "".join(f"{sha}  {name}\n" for name,sha in sorted(sums.items())))
            signed["assets"]=[
                {"name":file.name,"state":"uploaded",
                 "digest":"sha256:"+release.digest(file)}
                for file in folder.iterdir()]
            with self.assertRaises(release.Denied):
                release.verify_payload(folder,signed,manifest,contract,commit,[14,15])
            got,_,run=release.verify_payload(
                folder,signed,manifest,contract,commit,[14,15],
                expected_event="push")
            self.assertEqual(run,SRC_RUN)
            self.assertEqual(len(got),7)
            with ZipFile(zips[0]) as z:
                info=json.loads(z.read("PACKAGE-INFO.json"))
            info["workflowRun"]["attempt"]=2
            with self.assertRaises(release.Denied):
                release.check_source_package(
                    info,REPO,commit,14,
                    {"repository":"ossc-db/pg_hint_plan",
                     **manifest["upstream"]["perPostgresql"]["14"]},
                    expected_event="push")

if __name__=="__main__":unittest.main()
