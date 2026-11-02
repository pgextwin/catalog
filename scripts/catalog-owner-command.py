#!/usr/bin/env python3
"""Authenticate an immutable owner issue-comment input to signed Catalog reconciliation.

Only scopes public Release discovery; the existing independent per-asset
verifier and Catalog proposer App still retain every publication safety gate.
"""
import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

ISSUE=184
OWNER="ShutenOishi"
OWNER_ID=27071164
CMD=re.compile(r"^/pgextwin catalog ([a-z][a-z0-9_]*) (v[0-9]+(?:\.[0-9]+){1,3}(?:-[0-9]{8})?-windows\.[1-9][0-9]*)$")
ISSUE_URL="https://api.github.com/repos/pgextwin/catalog/issues/184"
class Denied(ValueError):pass
def require(ok,msg):
    if not ok:raise Denied(msg)
def owner(value):
    return type(value) is dict and value.get("login")==OWNER and type(value.get("id")) is int and value["id"]==OWNER_ID and value.get("type")=="User"
def identify(event):
    require(type(event) is dict and event.get("action")=="created"
            and owner(event.get("sender"))
            and type(event.get("issue")) is dict
            and event["issue"].get("number")==ISSUE
            and "pull_request" not in event["issue"],
            "untrusted owner Issue event")
    comment=event.get("comment")
    require(type(comment) is dict and type(comment.get("id")) is int
            and comment["id"]>0 and owner(comment.get("user"))
            and comment.get("issue_url")==ISSUE_URL
            and comment.get("created_at")==comment.get("updated_at"),
            "untrusted, edited or misplaced comment")
    body=comment.get("body")
    match=CMD.fullmatch(body) if type(body) is str else None
    require(match is not None,"malformed one-extension Catalog request")
    return comment["id"],match.group(1),match.group(2)

def verify(event,comment):
    cid,name,tag=identify(event)
    require(type(comment) is dict and comment.get("id")==cid
            and owner(comment.get("user"))
            and comment.get("issue_url")==ISSUE_URL
            and comment.get("body")==f"/pgextwin catalog {name} {tag}"
            and comment.get("created_at")==comment.get("updated_at"),
            "GitHub comment GET changed or forged")
    return name,tag

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--github-output",required=True)
    args=p.parse_args()
    try:
        env=os.environ
        require(env.get("GITHUB_REPOSITORY")=="pgextwin/catalog"
                and env.get("GITHUB_REF")=="refs/heads/main"
                and env.get("GITHUB_EVENT_NAME")=="issue_comment"
                and env.get("GITHUB_RUN_ATTEMPT")=="1"
                and env.get("GITHUB_ACTOR")==OWNER
                and env.get("GITHUB_TRIGGERING_ACTOR")==OWNER
                and env.get("GITHUB_ACTOR_ID")==str(OWNER_ID),
                "untrusted protected Catalog owner runtime")
        data=Path(env["GITHUB_EVENT_PATH"]).read_bytes()
        require(len(data)<32768,"oversized GitHub event")
        event=json.loads(data)
        cid,_,_=identify(event)
        token=env.get("GH_TOKEN")
        require(type(token) is str and len(token)>20,"read token unavailable")
        url=f"https://api.github.com/repos/pgextwin/catalog/issues/comments/{cid}"
        request=urllib.request.Request(url,method="GET",headers={
            "Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
            "User-Agent":"pgextwin-catalog-owner-reconcile"})
        with urllib.request.urlopen(request,timeout=20) as reply:
            require(reply.status==200 and reply.url==url,"untrusted redirect/status")
            body=reply.read(32769)
            require(len(body)<32769,"oversized comment GET")
        name,tag=verify(event,json.loads(body))
        with open(args.github_output,"a",encoding="utf-8") as out:
            out.write("extension="+name+"\n")
            out.write("release_tag="+tag+"\n")
        print("AUTHENTIC_OWNER_CATALOG_INPUT_ONLY: "+name+" "+tag)
        return 0
    except Exception as exc:
        print("CATALOG_OWNER_COMMAND_DENY ("+type(exc).__name__+")",file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
