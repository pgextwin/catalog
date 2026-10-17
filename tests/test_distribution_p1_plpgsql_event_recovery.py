#!/usr/bin/env python3
"""Hostile tests for exactly scoped, NOT-YET-ADMITTED plpgsql_check evidence."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from distribution_manifest_v1 import Denied
import distribution_p1_plpgsql_event_recovery as recovery


def event():
    return {"id":recovery.EVENT_ID, "type":"ReleaseEvent",
            "created_at":recovery.EVENT_TIME,
            "repo":{"id":recovery.REPO_ID,"name":recovery.REPO},
            "actor":{"id":recovery.ACTOR_ID,"login":"github-actions[bot]"},
            "payload":{"action":"published","release":{
                "id":recovery.RELEASE_ID,"tag_name":recovery.TAG,
                "target_commitish":recovery.PACKAGING,"draft":False,
                "published_at":recovery.EVENT_TIME}}}


def run():
    return {"id":recovery.RUN_ID,"run_attempt":1,
            "head_sha":recovery.PACKAGING,
            "repository":{"id":recovery.REPO_ID,"full_name":recovery.REPO},
            "event":"workflow_dispatch","path":".github/workflows/promote.yml",
            "head_branch":"main","status":"completed","conclusion":"failure"}


def jobs():
    rows=[{"id":jid,"name":f"Fresh attested Windows maintained PG14–18 build from validated main / PostgreSQL {pg} / Windows x64",
           "conclusion":"success","run_attempt":1}
          for pg,jid in recovery.ORIGINAL_JOBS.items()]
    rows.append({"id":recovery.PUBLISH_JOB,
                 "name":"Verify signatures and SHA; create-only formal publication",
                 "conclusion":"failure","run_attempt":1})
    return {"total_count":len(rows),"jobs":rows}


def release():
    rows=[]
    for pg, digest in recovery.PG_ZIPS.items():
        rows.append({"id":pg,"name":f"plpgsql_check-v2.10.14-pg{pg}-windows-x64.zip",
                     "state":"uploaded","digest":"sha256:"+digest})
        rows.append({"id":100+pg,"name":f"plpgsql_check-v2.10.14-pg{pg}-windows-x64.spdx.json",
                     "state":"uploaded","digest":"sha256:"+"1"*64})
        rows.append({"id":200+pg,"name":f"plpgsql_check-v2.10.14-pg{pg}-windows-x64.vulnerabilities.json",
                     "state":"uploaded","digest":"sha256:"+"2"*64})
    rows.append({"id":999,"name":"SHA256SUMS.txt","state":"uploaded",
                 "digest":"sha256:"+"3"*64})
    return {"id":recovery.RELEASE_ID,"tag_name":recovery.TAG,
            "target_commitish":recovery.PACKAGING,"draft":False,
            "prerelease":False,"published_at":recovery.EVENT_TIME,
            "assets":rows}


class RecoveryHostile(unittest.TestCase):
    def test_exact_event_canonical_and_independent_digest(self):
        raw=recovery.canonical(recovery.event_snapshot(event()))
        digest=hashlib.sha256(raw).hexdigest()
        self.assertEqual(recovery.verify_event_snapshot(raw,digest)["eventId"],
                         recovery.EVENT_ID)
        for field, value in [
            ("id","16939274946"),("type","PushEvent"),
            ("created_at","2026-10-11T09:36:21Z")]:
            with self.subTest(field=field),self.assertRaises(Denied):
                bad=event();bad[field]=value
                recovery.event_snapshot(bad)
        for path, badval in [
            (("repo","id"),1),(("repo","name"),"evil/plpgsql_check"),
            (("actor","id"),1),(("actor","login"),"ShutenOishi"),
            (("payload","action"),"created"),
            (("payload","release","id"),409572203),
            (("payload","release","tag_name"),"untrusted"),
            (("payload","release","target_commitish"),"f"*40),
            (("payload","release","draft"),True),
            (("payload","release","published_at"),"2026-10-11T10:46:27Z")]:
            bad=event();at=bad
            for key in path[:-1]:at=at[key]
            at[path[-1]]=badval
            with self.subTest(path=path), self.assertRaises(Denied):
                recovery.event_snapshot(bad)
        for wrong in ("0"*64, None):
            with self.subTest(wrong=wrong),self.assertRaises(Denied):
                recovery.verify_event_snapshot(raw,wrong)
        altered=raw.replace(b"published",b"publishED")
        with self.assertRaises(Denied):
            recovery.verify_event_snapshot(altered,hashlib.sha256(altered).hexdigest())
        with self.assertRaises(Denied):
            recovery.verify_event_snapshot(raw.strip(),hashlib.sha256(raw.strip()).hexdigest())

    def test_run_must_remain_failure_and_all_five_builds_succeed(self):
        self.assertTrue(recovery.validate_original_run(run(),jobs()))
        scenarios=[
            ("success-forged",lambda r,j:r.update(conclusion="success")),
            ("wrong-sha",lambda r,j:r.update(head_sha="0"*40)),
            ("wrong-repo",lambda r,j:r["repository"].update(id=10)),
            ("wrong-run-id",lambda r,j:r.update(id=1)),
            ("attempt-2",lambda r,j:r.update(run_attempt=2)),
            ("publisher-success-forged",lambda r,j:j["jobs"][-1].update(conclusion="success")),
            ("publisher-missing",lambda r,j:j["jobs"].pop()),
            ("pg18-failure",lambda r,j:j["jobs"][4].update(conclusion="failure")),
            ("pg17-retry",lambda r,j:j["jobs"][3].update(run_attempt=2)),
            ("truncated-page",lambda r,j:j.update(total_count=100)),
            ("duplicated-job",lambda r,j:j["jobs"][0].update(id=j["jobs"][1]["id"])),
        ]
        for name,mutate in scenarios:
            a,b=run(),jobs();mutate(a,b)
            with self.subTest(name=name),self.assertRaises(Denied):
                recovery.validate_original_run(a,b)

    def test_release_all_16_assets_pinned_and_per_pg_digests(self):
        a=release(); pins={i["name"]:i["id"] for i in a["assets"]}
        digests={i["name"]:i["digest"][7:] for i in a["assets"]}
        self.assertEqual(len(recovery.validate_original_release(a,pins,digests)),16)
        for name,change in [
            ("replaced-asset-id",lambda x:x["assets"][0].update(id=42)),
            ("missing-asset",lambda x:x["assets"].pop()),
            ("changed-pg18-digest",lambda x:x["assets"][12].update(digest="sha256:"+"0"*64)),
            ("duplicate",lambda x:x["assets"][1].update(name=x["assets"][0]["name"])),
            ("draft",lambda x:x.update(draft=True)),
            ("tag-sha",lambda x:x.update(target_commitish="f"*40))]:
            bad=copy.deepcopy(a);change(bad)
            with self.subTest(name=name),self.assertRaises(Denied):
                recovery.validate_original_release(bad,pins,digests)

    def test_original_artifact_metadata_not_fake_sha(self):
        a=[{"id":n,"name":k,"digest":"sha256:"+digest,"expired":False}
           for k,(n,digest) in recovery.ARTIFACTS.items()]
        a.extend({"id":number,"name":f"plpgsql_check-pg{pg}-windows-x64",
                  "digest":"sha256:"+digest,"expired":False}
                 for pg,(number,digest) in recovery.BUILD_ARTIFACTS.items())
        self.assertTrue(recovery.validate_artifact_metadata(a))
        for name,alter in [
            ("missing",lambda b:b.pop()),
            ("digest",lambda b:b[0].update(digest="sha256:"+"0"*64)),
            ("expired",lambda b:b[1].update(expired=True)),
            ("wrong-id",lambda b:b[1].update(id=99)),
            ("pg18-substitution",lambda b:b[-1].update(digest="sha256:"+"e"*64))]:
            b=copy.deepcopy(a);alter(b)
            with self.subTest(name=name),self.assertRaises(Denied):
                recovery.validate_artifact_metadata(b)

    def test_missing_original_build_archive_cannot_qualify(self):
        with self.assertRaises(Denied):
            recovery.verify_original_build_archive(18,Path("missing"),{})

    def test_fail_closed_unanchored_causal_link(self):
        data=json.loads(recovery.ANCHOR.read_text())
        self.assertIsNone(data["eventCanonicalSha256"])
        self.assertFalse(data["causalBridgeIndependentlyVerified"])
        with self.assertRaises(Denied):
            recovery.require_causal_bridge(data)
        data["eventCanonicalSha256"]="a"*64
        data["causalBridgeIndependentlyVerified"]=True
        data["causalBridgeEvidenceSha256"]="b"*64
        with self.assertRaises(Denied):
            recovery.require_causal_bridge(data)

    def test_never_invoke_crypto_as_fixture(self):
        with patch.object(recovery,"verify_sigstore_offline",
                          side_effect=AssertionError("should not be called")):
            with self.assertRaises(Denied):
                recovery.verify_original_pg_sigstore(
                    pg=19,zip_path=Path("missing"),sbom_path=Path("missing"),
                    bundle_path=Path("missing"),bundle_sha256="0"*64,
                    root_path=Path("missing"),root_sha256="0"*64)


if __name__ == "__main__":
    unittest.main()
