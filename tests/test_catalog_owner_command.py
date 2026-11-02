#!/usr/bin/env python3
"""Offline hostile fixtures: only an immutable owner #184 request is admitted."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("catalog_owner_command",ROOT/"scripts/catalog-owner-command.py")
command=importlib.util.module_from_spec(spec)
spec.loader.exec_module(command)
CID=6579818986
NAME="hypopg"
TAG="v1.4.5-windows.1"
OWNER={"login":"ShutenOishi","id":27071164,"type":"User"}
def event():
    return {"action":"created","issue":{"number":184},
            "sender":dict(OWNER),"comment":{
                "id":CID,"user":dict(OWNER),
                "issue_url":"https://api.github.com/repos/pgextwin/catalog/issues/184",
                "body":f"/pgextwin catalog {NAME} {TAG}",
                "created_at":"2026-11-02T14:46:54Z",
                "updated_at":"2026-11-02T14:46:54Z"}}
def live():
    return dict(event()["comment"])

class OwnerCatalogCommand(unittest.TestCase):
    def test_authentic_owner_is_one_record_and_exact_tag(self):
        self.assertEqual(command.identify(event()),(CID,NAME,TAG))
        self.assertEqual(command.verify(event(),live()),(NAME,TAG))
    def test_reject_edited_forged_other_issue_scope_and_bad_tags(self):
        bad=[]
        for key,val in (("action","edited"),("action","deleted")):
            x=event();x[key]=val;bad.append(x)
        for n in (75,185,0):
            x=event();x["issue"]["number"]=n;bad.append(x)
        x=event();x["issue"]["pull_request"]={"url":"https://github.com"};bad.append(x)
        for field,val in (("body",f"/pgextwin catalog {NAME} {TAG}\n"),
                          ("body","/pgextwin catalog hypopg latest"),
                          ("body","/pgextwin catalog hypopg v1.4.4-windows.1 extra"),
                          ("body","/pgextwin catalog ../hypopg v1.4.5-windows.1"),
                          ("updated_at","2026-11-02T14:46:55Z"),
                          ("issue_url","https://api.github.com/repos/pgextwin/catalog/issues/185"),
                          ("id",0)):
            x=event();x["comment"][field]=val;bad.append(x)
        for field in ("sender","comment"):
            for key,val in (("login","attacker"),("id",1),("type","Bot")):
                x=event()
                if field=="sender":x["sender"][key]=val
                else:x["comment"]["user"][key]=val
                bad.append(x)
        for i,x in enumerate(bad):
            with self.subTest(i=i),self.assertRaises(command.Denied):
                command.identify(x)
    def test_live_comment_must_match_original_event(self):
        for field,value in (("body","/pgextwin catalog plpgsql_check v2.10.16-windows.1"),
                            ("issue_url","https://api.github.com/repos/pgextwin/catalog/issues/311"),
                            ("id",CID+1),("updated_at","2026-11-02T14:46:55Z")):
            x=live();x[field]=value
            with self.subTest(field=field),self.assertRaises(command.Denied):
                command.verify(event(),x)
    def test_readonly_main_runner_authenticates_and_writes_exact_lines(self):
        class Response:
            status=200
            url=f"https://api.github.com/repos/pgextwin/catalog/issues/comments/{CID}"
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def read(self,n):return json.dumps(live()).encode()
        with tempfile.TemporaryDirectory() as d:
            e=Path(d)/"event.json";e.write_text(json.dumps(event()))
            o=Path(d)/"out"
            env={"GITHUB_REPOSITORY":"pgextwin/catalog","GITHUB_REF":"refs/heads/main",
                 "GITHUB_EVENT_NAME":"issue_comment","GITHUB_RUN_ATTEMPT":"1",
                 "GITHUB_ACTOR":"ShutenOishi","GITHUB_TRIGGERING_ACTOR":"ShutenOishi",
                 "GITHUB_ACTOR_ID":"27071164","GITHUB_EVENT_PATH":str(e),
                 "GH_TOKEN":"synthetic-read-token-more-than-20-characters"}
            with patch.dict("os.environ",env),patch("sys.argv",["cmd","--github-output",str(o)]),patch.object(command.urllib.request,"urlopen",return_value=Response()) as fetch:
                self.assertEqual(command.main(),0)
                self.assertEqual(o.read_text(),f"extension={NAME}\nrelease_tag={TAG}\n")
                fetch.assert_called_once()
            with patch.dict("os.environ",dict(env,GITHUB_ACTOR_ID="1")),patch("sys.argv",["cmd","--github-output",str(o)]),patch.object(command.urllib.request,"urlopen") as fetch:
                self.assertEqual(command.main(),2)
                fetch.assert_not_called()

if __name__=="__main__":unittest.main()
