"""Adversarial protected Catalog request tests; fixtures are not real signatures."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import catalog_chat_request as m

SHA, BASE, HEAD = "a"*40, "b"*40, "c"*40
TAG, EXT = "v1.0.0-windows.1", "pgtap"
HUMAN = {"login":"ShutenOishi","type":"User"}


def request():
    return {"schemaVersion":1,"type":"pgextwin-public-release-catalog-verification",
            "extension":EXT,"releaseTag":TAG,"releaseId":50,"catalogBaseSha":BASE,
            "operatorLogin":"ShutenOishi","confirmCatalog":"VERIFY_PUBLIC_RELEASE"}


class Fake:
    def __init__(self,data): self.data,self.calls=data,[]
    def get(self,repo,path):
        m.RequestReader.allowlisted(repo,path)
        self.calls.append((repo,path))
        return deepcopy(self.data[(repo,path)])


def fixture(with_request=True):
    env={"GITHUB_REPOSITORY":m.REPO,"GITHUB_EVENT_NAME":"push","GITHUB_REF":"refs/heads/main",
         "GITHUB_RUN_ATTEMPT":"1","GITHUB_SHA":SHA,"GITHUB_RUN_ID":"100","GITHUB_ACTOR":"ShutenOishi"}
    event={"repository":{"full_name":m.REPO},"ref":"refs/heads/main","after":SHA,"before":BASE,
           "created":False,"deleted":False,"commits":[{"id":SHA}],"sender":dict(HUMAN)}
    raw=json.dumps(request()).encode()
    path=m.PREFIX+EXT+"-"+TAG+".json"
    files=[{"filename":path,"sha":m.blob_sha(raw),"status":"added"}] if with_request else [
        {"filename":"docs/setup.md","sha":"d"*40,"status":"added"}]
    pr={"number":1,"merged":True,"state":"closed","merge_commit_sha":SHA,"changed_files":1,
        "user":dict(HUMAN),"merged_by":dict(HUMAN),
        "head":{"sha":HEAD,"ref":"catalog-verify/"+EXT+"-"+TAG,"repo":{"full_name":m.REPO}},
        "base":{"ref":"main","repo":{"full_name":m.REPO}}}
    data={(m.REPO,"actions/runs/100"):{"id":100,"event":"push","path":m.WORKFLOW,"head_branch":"main",
         "repository":{"full_name":m.REPO},"head_sha":SHA,"run_attempt":1,"actor":dict(HUMAN),"triggering_actor":dict(HUMAN)},
        (m.REPO,"branches/main"):{"protected":True,"commit":{"sha":SHA},"protection":{
            "required_status_checks":{"checks":[{"context":"validate","app_id":15368}]}}},
        (m.REPO,"commits/"+SHA):{"sha":SHA,"parents":[{"sha":BASE}],"files":files,
            "commit":{"verification":{"verified":True,"reason":"valid"}},"committer":{"login":"web-flow"}},
        (m.REPO,"commits/"+SHA+"/pulls?per_page=100"):[pr],
        (m.REPO,"pulls/1"):pr,(m.REPO,"pulls/1/files?per_page=100"):files,
        (m.REPO,"commits/"+HEAD+"/check-runs?per_page=100"):{"total_count":1,"check_runs":[{
            "name":"validate","app":{"id":15368},"head_sha":HEAD,"status":"completed","conclusion":"success"}]},
        (m.REPO,"contents/"+path+"?ref="+SHA):{"path":path,"type":"file","encoding":"base64",
            "content":base64.b64encode(raw).decode(),"size":len(raw),"sha":m.blob_sha(raw)},
        ("pgextwin/"+EXT,"releases/tags/"+TAG):{"id":50,"tag_name":TAG,"draft":False,"prerelease":False,
            "published_at":"2026-10-20T00:00:00Z","target_commitish":"e"*40,"assets":[{
                "id":20,"name":"real-in-fixture.zip","size":123,"digest":"sha256:"+"f"*64,"download_count":0}]}}
    return env,event,data


class CatalogChatRequestTests(unittest.TestCase):
    def test_exact_request_resolution_is_not_signature_acceptance(self):
        env,event,data=fixture()
        self.assertEqual(m.resolve(Fake(data),env,event),request())

    def test_setup_without_request_does_not_fetch_or_verify_release(self):
        env,event,data=fixture(False)
        api=Fake(data)
        self.assertIsNone(m.resolve(api,env,event))
        self.assertFalse(any("releases" in path for repo,path in api.calls))

    def test_closed_schema_rejects_unknown_duplicate_missing_bot_and_publish(self):
        for field,value in (("extra",1),("confirmCatalog","PUBLISH"),("extension","evil"),
                            ("releaseId",True),("releaseId",0),("catalogBaseSha","old"),
                            ("schemaVersion",True),("releaseTag","../x"),("operatorLogin","github-actions[bot]")):
            r=request();r[field]=value
            with self.subTest(field=field),self.assertRaises((m.Denied,ValueError,TypeError)):
                m.parse(json.dumps(r).encode())
        for raw in (b"{}",b"[]",json.dumps(request()).encode().replace(b'"schemaVersion": 1',b'"schemaVersion":1,"schemaVersion":1'),b'x'*16385):
            with self.assertRaises((m.Denied,ValueError)):
                m.parse(raw)

    def test_runtime_pr_actor_blob_and_ci_rejections(self):
        cases=[lambda e,v,d:e.update(GITHUB_RUN_ATTEMPT="2"),lambda e,v,d:e.update(GITHUB_EVENT_NAME="pull_request"),
               lambda e,v,d:v.update(before=HEAD),lambda e,v,d:v["sender"].update(type="Bot"),
               lambda e,v,d:v["commits"].append({"id":SHA}),
               lambda e,v,d:d[(m.REPO,"branches/main")].update(protected=False),
               lambda e,v,d:d[(m.REPO,"commits/"+SHA)]["commit"]["verification"].update(verified=False),
               lambda e,v,d:d[(m.REPO,"pulls/1")]["merged_by"].update(type="Bot"),
               lambda e,v,d:d[(m.REPO,"pulls/1")]["user"].update(login="other"),
               lambda e,v,d:d[(m.REPO,"pulls/1")].update(merged=False),
               lambda e,v,d:d[(m.REPO,"pulls/1")]["head"]["repo"].update(full_name="pgextwin/evil"),
               lambda e,v,d:d[(m.REPO,"commits/"+SHA+"/pulls?per_page=100")].append({"number":2}),
               lambda e,v,d:d[(m.REPO,"commits/"+HEAD+"/check-runs?per_page=100")].update(total_count=100),
               lambda e,v,d:d[(m.REPO,"commits/"+HEAD+"/check-runs?per_page=100")]["check_runs"][0].update(conclusion="skipped"),
               lambda e,v,d:d[(m.REPO,"commits/"+HEAD+"/check-runs?per_page=100")]["check_runs"][0].update(head_sha=BASE),
               lambda e,v,d:d[(m.REPO,"commits/"+HEAD+"/check-runs?per_page=100")]["check_runs"][0].update(app={"id":1}),
               lambda e,v,d:d[(m.REPO,"commits/"+SHA)]["files"][0].update(status="modified")]
        for i,mutate in enumerate(cases):
            env,event,data=fixture();mutate(env,event,data)
            with self.subTest(case=i),self.assertRaises((m.Denied,ValueError,KeyError,TypeError)):
                m.resolve(Fake(data),env,event)

    def test_public_release_id_and_draft_candidates_denied(self):
        for field,value in (("id",51),("draft",True),("prerelease",True),("published_at",None),("target_commitish","main")):
            env,event,data=fixture();data[("pgextwin/"+EXT,"releases/tags/"+TAG)][field]=value
            with self.subTest(field=field),self.assertRaises(m.Denied):
                m.resolve(Fake(data),env,event)

    def test_existing_verifier_is_mandatory_and_release_changes_deny(self):
        env,event,data=fixture();api=Fake(data);calls=[]
        def signed_mock(ext,tag,path):
            calls.append((ext,tag,path))
            return {"synthetic":True},{"status":"VERIFIED","repository":"pgextwin/"+EXT,"tag":TAG}
        mapped,audit=m.verify(api,request(),signed_mock)
        self.assertEqual(calls,[(EXT,TAG,Path("extensions/pgtap.json"))])
        self.assertTrue(mapped["synthetic"])
        def unsigned(ext,tag,path): return {},{"status":"INTEGRITY_ONLY","repository":"pgextwin/"+EXT,"tag":TAG}
        with self.assertRaises(m.Denied):m.verify(Fake(data),request(),unsigned)
        def changed(ext,tag,path):
            data[("pgextwin/"+EXT,"releases/tags/"+TAG)]["assets"][0]["digest"]="sha256:"+"0"*64
            return signed_mock(ext,tag,path)
        with self.assertRaises(m.Denied):m.verify(Fake(data),request(),changed)

    def test_download_count_is_not_immutable_identity(self):
        env,event,data=fixture();api=Fake(data)
        first=m.release_identity(api,request())
        data[("pgextwin/"+EXT,"releases/tags/"+TAG)]["assets"][0]["download_count"]+=1
        self.assertEqual(first,m.release_identity(api,request()))

    def test_request_reader_cannot_write_or_read_secret_or_unknown_target(self):
        for repo,path in ((m.REPO,"secrets"),(m.REPO,"actions/runs/1/rerun"),(m.REPO,"git/refs"),
                          ("pgextwin/evil","releases/tags/"+TAG),(m.REPO,"https://evil.test")):
            with self.assertRaises(m.Denied):m.RequestReader.allowlisted(repo,path)

    def test_committed_requests_have_exact_schema_and_matching_filename(self):
        for file in (ROOT/m.PREFIX).glob("*.json"):
            r=m.parse(file.read_bytes())
            self.assertEqual(file.name,r["extension"]+"-"+r["releaseTag"]+".json")

    def test_workflow_has_no_release_app_secret_merge_or_dispatch_capability(self):
        text=(ROOT/".github/workflows/catalog-chat-request.yml").read_text()
        self.assertIsNone(re.search(r"^\s+[a-z-]+:\s*write\s*$",text,re.M))
        for forbidden in ("secrets.", "create-github-app-token", "workflow_dispatch:", "gh pr", "gh release"):
            self.assertNotIn(forbidden,text)
        self.assertIn("persist-credentials: false",text)
        self.assertIn("ref: ${{ github.sha }}",text)
        self.assertIn("steps.verify.outputs.verified == 'true'",text)


if __name__ == "__main__": unittest.main()
