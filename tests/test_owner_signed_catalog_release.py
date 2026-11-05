#!/usr/bin/env python3
"""#524 offline Catalog hostile owner-signing source kind / genuine original GET contract."""
from copy import deepcopy
import json
from unittest import TestCase
from scripts import automatic_publisher_provenance as p
from scripts import verify_signed_fleet_release as v

REPO="pgextwin/plpgsql_check"
SHA="a"*40
PUBSHA="b"*40
SRC=41486380278
PUB=41542943076
SIGN=6583019297
REQUEST=6590781546
TAG="v2.10.16-windows.1"
OWNER={"login":"ShutenOishi","id":27071164,"type":"User"}

def fixture():
    owner={"login":"ShutenOishi","id":27071164,"type":"User"}
    marker={"schemaVersion":1,"authorizationMode":"owner-signed-main-issue-comment",
            "repository":REPO,"releaseTag":TAG,"packagingCommit":SHA,
            "sourceRunId":SRC,"sourceRunAttempt":1,
            "sourceWorkflow":p.OWNER_SOURCE,"publisherRepository":"pgextwin/build",
            "publisherRunId":PUB,"publisherRunAttempt":1,"publisherMainSha":PUBSHA,
            "publisherWorkflow":p.PUBLISHER,"publisherAppId":5451798,
            "approvalProvenance":"INDEPENDENT_LIVE_OWNER_MAIN_SIGNING_AND_PUBLISH_REQUEST",
            "requestCommentId":REQUEST,"sourceSigningCommentId":SIGN,
            "sourceKind":"OWNER_ISSUE_COMMENT_MAIN_SIGNING"}
    notes=p.PREFIX+json.dumps(marker,sort_keys=True,separators=(",",":"))+p.SUFFIX
    source={"id":SRC,"event":"issue_comment","path":p.OWNER_SOURCE,
            "run_attempt":1,"head_sha":SHA,"head_branch":"main",
            "status":"completed","conclusion":"success",
            "display_title":f"Chat-main-sign-comment-{SIGN}",
            "repository":{"full_name":REPO},"actor":dict(owner),"triggering_actor":dict(owner),
            "created_at":"2026-11-02T16:56:43Z"}
    publisher={"id":PUB,"event":"issue_comment","path":p.PUBLISHER,
            "run_attempt":1,"head_sha":PUBSHA,"head_branch":"main",
            "status":"completed","conclusion":"success",
            "display_title":f"Publisher-issue_comment-comment-{REQUEST}",
            "repository":{"full_name":"pgextwin/build"},
            "actor":dict(owner),"triggering_actor":dict(owner),
            "created_at":"2026-11-02T18:00:00Z",
            "updated_at":"2026-11-02T18:25:00Z"}
    def comment(id,body,repo,issue,time):
        return {"id":id,"user":dict(owner),"body":body,
                "issue_url":f"https://api.github.com/repos/{repo}/issues/{issue}",
                "created_at":time,"updated_at":time}
    signing=comment(SIGN,"/pgextwin sign-main",REPO,78,"2026-11-02T16:55:00Z")
    publishing=comment(REQUEST,f"/pgextwin publish-owner-source {REPO} {SRC}",
                       "pgextwin/build",311,"2026-11-02T17:55:00Z")
    jobs={"total_count":2,"jobs":[
        {"id":1,"name":p.OWNER_ADMIT_JOB,"run_id":PUB,
         "run_attempt":1,"head_sha":PUBSHA,
         "status":"completed","conclusion":"success"},
        {"id":2,"name":p.OWNER_PUBLISH_JOB,"run_id":PUB,
         "run_attempt":1,"head_sha":PUBSHA,
         "status":"completed","conclusion":"success"}]}
    release={"tag_name":TAG,"target_commitish":SHA,"draft":False,
             "prerelease":False,
             "author":{"login":"pgextwin-publisher[bot]","type":"Bot"},
             "body":notes,"published_at":"2026-11-02T18:15:00Z"}
    return dict(marker=marker,release=release,source=source,publisher=publisher,
                signing=signing,publishing=publishing,jobs=jobs)

def verify_case(x, repository=REPO):
    paths={
        f"repos/{repository}/actions/runs/{SRC}":x["source"],
        f"repos/pgextwin/build/actions/runs/{PUB}":x["publisher"],
        f"repos/{repository}/issues/comments/{SIGN}":x["signing"],
        f"repos/pgextwin/build/issues/comments/{REQUEST}":x["publishing"],
        f"repos/pgextwin/build/actions/runs/{PUB}/attempts/1/jobs?per_page=100":x["jobs"]}
    def api(path):
        if path not in paths:raise AssertionError("unexpected external GET "+path)
        return paths[path]
    return p.verify(release=x["release"],repository=repository,tag=x["marker"]["releaseTag"],
                    sha=SHA,source_run_id=SRC,
                    marker=p.parse(x["release"]["body"]),api=api)

class OwnerSignedCatalogTests(TestCase):
    def test_authentic_source_and_distinct_publisher_is_only_locator(self):
        result=verify_case(fixture())
        self.assertEqual(result["status"],
                         "INDEPENDENT_OWNER_MAIN_SIGNING_PUBLISHER_LIVE_MATCH")
        self.assertTrue(result["sigstoreReleaseBytesMustBeVerifiedSeparately"])

    def test_original_signer_publisher_spoof_or_replay_denied(self):
        mutations=[
            lambda x:x["source"].update(event="push"),
            lambda x:x["source"].update(path=p.SOURCE),
            lambda x:x["source"].update(run_attempt=2),
            lambda x:x["source"].update(conclusion="failure"),
            lambda x:x["source"].update(display_title="fake"),
            lambda x:x["source"]["actor"].update(id=1),
            lambda x:x["source"]["triggering_actor"].update(login="attacker"),
            lambda x:x["signing"].update(body="/pgextwin publish"),
            lambda x:x["signing"].update(updated_at="2026-11-03T00:00:00Z"),
            lambda x:x["signing"]["user"].update(id=1),
            lambda x:x["publishing"].update(body="/pgextwin publish "+REPO),
            lambda x:x["publishing"].update(updated_at="2026-11-03T00:00:00Z"),
            lambda x:x["publisher"].update(event="schedule"),
            lambda x:x["publisher"].update(run_attempt=2),
            lambda x:x["jobs"]["jobs"][0].update(conclusion="failure"),
            lambda x:x["jobs"]["jobs"][1].update(conclusion="skipped"),
            lambda x:x["jobs"]["jobs"][1].update(name=p.PUBLISH_JOB+" (plpgsql_check)"),
            lambda x:x["release"].update(draft=True),
        ]
        for i,mutate in enumerate(mutations):
            x=fixture()
            mutate(x)
            with self.subTest(i=i),self.assertRaises(p.Denied):
                verify_case(x)

    def test_set_user_owner_signer_bound_to_exact_issue_60_and_immutable_original(self):
        repo="pgextwin/set_user"
        x=fixture()
        x["marker"]["repository"]=repo
        x["marker"]["releaseTag"]="v4.3.0-windows.1"
        x["source"]["repository"]["full_name"]=repo
        x["signing"]["issue_url"]=f"https://api.github.com/repos/{repo}/issues/60"
        x["publishing"]["body"]=f"/pgextwin publish-owner-source {repo} {SRC}"
        x["release"]["tag_name"]=x["marker"]["releaseTag"]
        x["release"]["body"]=p.PREFIX+json.dumps(
            x["marker"],sort_keys=True,separators=(",",":"))+p.SUFFIX
        result=verify_case(x,repository=repo)
        self.assertEqual(result["status"],
                         "INDEPENDENT_OWNER_MAIN_SIGNING_PUBLISHER_LIVE_MATCH")
        self.assertTrue(result["sigstoreReleaseBytesMustBeVerifiedSeparately"])
        mutants=[
            lambda y:y["signing"].update(
                issue_url=f"https://api.github.com/repos/{repo}/issues/78"),
            lambda y:y["signing"].update(
                issue_url=f"https://api.github.com/repos/{repo}/issues/61"),
            lambda y:y["signing"].update(updated_at="2026-11-02T16:55:01Z"),
            lambda y:y["signing"].update(body="/pgextwin publish"),
            lambda y:y["source"].update(display_title="Chat-main-sign-comment-0"),
            lambda y:y["source"].update(run_attempt=2),
            lambda y:y["source"]["actor"].update(login="attacker"),
            lambda y:y["source"]["triggering_actor"].update(id=123),
            lambda y:y["publishing"].update(
                body=f"/pgextwin publish-owner-source {repo} 999"),
            lambda y:y["jobs"]["jobs"][0].update(conclusion="failure"),
            lambda y:y["jobs"]["jobs"][1].update(conclusion="skipped"),
        ]
        for index,mutate in enumerate(mutants):
            with self.subTest(index=index),self.assertRaises(p.Denied):
                bad=deepcopy(x)
                mutate(bad)
                verify_case(bad,repository=repo)
        unknown=deepcopy(x)
        unknown_repo="pgextwin/pg_ivm"
        unknown["marker"]["repository"]=unknown_repo
        unknown["source"]["repository"]["full_name"]=unknown_repo
        unknown["signing"]["issue_url"]=(
            f"https://api.github.com/repos/{unknown_repo}/issues/67")
        unknown["publishing"]["body"]=(
            f"/pgextwin publish-owner-source {unknown_repo} {SRC}")
        unknown["release"]["body"]=p.PREFIX+json.dumps(
            unknown["marker"],sort_keys=True,separators=(",",":"))+p.SUFFIX
        with self.assertRaises(p.Denied):
            verify_case(unknown,repository=unknown_repo)

    def test_owner_source_cannot_coerce_push_or_manual(self):
        self.assertEqual(v.check_source_package(
            {"schemaVersion":1,"buildMode":"release-attested",
             "package":{"name":"plpgsql_check","platform":"windows","architecture":"x64"},
             "source":{"packagingRepository":REPO,"packagingCommit":SHA},
             "upstream":{"repository":"okbob/plpgsql_check","ref":"v2.10.16",
                         "version":"2.10.16","commit":"c"*40},
             "postgresql":{"major":18},
             "workflowRun":{"id":SRC,"event":"issue_comment",
                            "ref":"refs/heads/main","attempt":1}},
            REPO,SHA,18,{"repository":"okbob/plpgsql_check",
                         "ref":"v2.10.16","version":"2.10.16","commit":"c"*40},
            expected_event="issue_comment"),SRC)
        x=fixture()
        x["marker"]["sourceWorkflow"]=p.SOURCE
        x["release"]["body"]=p.PREFIX+json.dumps(x["marker"])+p.SUFFIX
        with self.assertRaises(p.Denied):
            verify_case(x)
