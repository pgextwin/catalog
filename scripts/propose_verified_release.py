#!/usr/bin/env python3
"""Step 21: generate one reviewable Catalog v2 PR change from a VERIFIED public Release.

The public Release, signed ZIP attestations, PACKAGE-INFO and Test Contract at the
trusted packaging commit are authoritative. Never infer missing assets.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from zipfile import ZipFile

REPOSITORY = "pgextwin/plpgsql_check"
EXT = "plpgsql_check"
COMMIT = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
TAG = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+)-windows\.[1-9][0-9]*$")
SIGNER = "pgextwin/build/.github/workflows/build-extension-attested.yml"

class UnsafeCatalog(ValueError): pass

def require(value, msg):
    if not value: raise UnsafeCatalog(msg)

def gh(*args):
    cmd=subprocess.run(("gh",)+args,capture_output=True,text=True)
    if cmd.returncode:
        raise UnsafeCatalog("GitHub call denied: "+" ".join(args[:3])+" "+cmd.stderr[:250])
    return cmd.stdout

def api(path):
    return json.loads(gh("api",path))

def pinned_json(commit, path):
    raw=api("repos/"+REPOSITORY+"/contents/"+path+"?ref="+commit)
    require(raw.get("encoding")=="base64" and isinstance(raw.get("content"),str),
            "pinned contract unavailable")
    return json.loads(base64.b64decode(raw["content"]).decode("utf-8"))

def digest(p):
    h=hashlib.sha256()
    with p.open("rb") as stream:
        for part in iter(lambda:stream.read(1024*1024),b""):h.update(part)
    return h.hexdigest()

def update_record(existing, release, manifests, contracts, assets, checksums, source_commit):
    """Pure Catalog v2 transformation for the one explicitly approved pilot extension."""
    ext=manifests
    tc=contracts
    require(existing.get("schemaVersion")==2 and existing.get("name")==EXT
            and existing.get("repository")==REPOSITORY,"unsupported catalog identity")
    require(ext["name"]==EXT and ext["upstream"]["repository"]=="okbob/plpgsql_check",
            "manifest identity changed")
    require(tc.get("contractVersion")==2 and tc.get("extension")==EXT,
            "Test Contract v2 mismatch")
    tag=release["tag_name"]
    match=TAG.fullmatch(tag)
    require(match and match.group(1)==ext["upstream"]["version"],"tag != manifest version")
    require(not release["draft"] and not release["prerelease"] and release.get("published_at"),
            "Release is not publicly published")
    major_set={str(x) for x in ext["postgresql"]["majors"]}
    require(major_set=={"15","16","17","18"},"pilot majors changed or missing")
    expected={"SHA256SUMS.txt"}
    for major in major_set:
        stem=EXT+"-v"+ext["upstream"]["version"]+"-pg"+major+"-windows-x64"
        expected.update({stem+".zip",stem+".spdx.json",stem+".vulnerabilities.json"})
    require(set(assets)==expected and set(checksums)==expected-{"SHA256SUMS.txt"},
            "partial/extra Release assets or checksums")
    for asset in expected:
        require(assets[asset]["name"]==asset
                and assets[asset]["state"]=="uploaded", "non-uploaded Release asset")
    updated=json.loads(json.dumps(existing))
    updated["upstream"]["version"]=ext["upstream"]["version"]
    updated["latest"]={
        "releaseTag":tag, "publishedAt":release["published_at"],
        "releaseUrl":"https://github.com/"+REPOSITORY+"/releases/tag/"+tag,
        "checksumsAsset":"SHA256SUMS.txt"
    }
    for major in sorted(major_set):
        stem=EXT+"-v"+ext["upstream"]["version"]+"-pg"+major+"-windows-x64"
        def entry(suffix):
            name=stem+suffix
            return {"available":True,"asset":name,
                    "downloadUrl":"https://github.com/"+REPOSITORY+"/releases/download/"+tag+"/"+name,
                    "sha256":checksums[name]}
        obj=entry(".zip")
        obj["evidence"]={
            "buildProvenanceAttestation":{"available":True},
            "sbom":entry(".spdx.json"),
            "sbomAttestation":{"available":True},
            "vulnerabilityReport":entry(".vulnerabilities.json")
        }
        updated["postgresql"][major]=obj
    updated["runtime"]["requirements"]=tc["runtimeRequirements"]
    updated["capabilities"]={
        "testContractVersion":2,
        "coverage":tc["coverage"],
        "functionalScenarios":tc["functionalScenarios"]
    }
    updated["capabilitiesSource"]={
        "repository":REPOSITORY,"path":"config/test-contract.json","commit":source_commit
    }
    return updated

def generate(extension, tag, dest):
    require(extension==EXT and TAG.fullmatch(tag) is not None,"pilot/tag not allowed")
    rel=api("repos/"+REPOSITORY+"/releases/tags/"+tag)
    require(rel.get("tag_name")==tag and not rel["draft"] and not rel["prerelease"]
            and rel.get("published_at"), "no publicly published immutable Release")
    assets={a["name"]:a for a in rel["assets"]}
    require(len(assets)==13,"expected exactly 13 Release assets")
    with tempfile.TemporaryDirectory() as temp:
        folder=Path(temp)
        gh("release","download",tag,"--repo",REPOSITORY,"--dir",temp)
        downloaded={p.name for p in folder.iterdir() if p.is_file()}
        require(downloaded==set(assets),"local download does not match Release assets")
        lines=(folder/"SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
        sums={}
        for line in lines:
            m=re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.-]+)",line)
            require(m is not None,"unparseable checksum entry")
            require(m.group(2) not in sums,"duplicate checksum line")
            sums[m.group(2)]=m.group(1)
        require(set(sums)==set(assets)-{"SHA256SUMS.txt"},"checksums incomplete")
        for filename,expected in sums.items():
            require(digest(folder/filename)==expected,"wrong remote ZIP/report digest")
        source_commit=None
        for major in (15,16,17,18):
            stem=EXT+"-v"+TAG.fullmatch(tag).group(1)+"-pg"+str(major)+"-windows-x64"
            zip_file=folder/(stem+".zip")
            with ZipFile(zip_file) as z:
                require(z.namelist().count("PACKAGE-INFO.json")==1,"missing PACKAGE-INFO")
                pkg=json.loads(z.read("PACKAGE-INFO.json").decode("utf-8-sig"))
            commit=pkg["source"]["packagingCommit"]
            require(COMMIT.fullmatch(commit) is not None,"unpinned package commit")
            source_commit=source_commit or commit
            require(commit==source_commit
                    and pkg["buildMode"]=="release-attested"
                    and pkg["package"]["name"]==EXT
                    and pkg["upstream"]["repository"]=="okbob/plpgsql_check"
                    and pkg["postgresql"]["major"]==major
                    and pkg["workflowRun"]["ref"]=="refs/heads/main"
                    and pkg["workflowRun"]["event"]=="workflow_dispatch",
                    "Release package metadata not from one approved main build")
            require(json.loads((folder/(stem+".spdx.json")).read_text(encoding="utf-8-sig"))["spdxVersion"]=="SPDX-2.3",
                    "not an SPDX 2.3 SBOM")
            require(isinstance(json.loads((folder/(stem+".vulnerabilities.json")).read_text(encoding="utf-8-sig"))["matches"],list),
                    "bad Grype JSON")
            # This is a NEW verification, independent of formal Release build workflow.
            gh("attestation","verify",str(zip_file),"--repo",REPOSITORY,"--signer-workflow",SIGNER)
            gh("attestation","verify",str(zip_file),"--repo",REPOSITORY,"--signer-workflow",SIGNER,
               "--predicate-type","https://spdx.dev/Document/v2.3")
        ancestry=api("repos/"+REPOSITORY+"/compare/"+source_commit+"...main")
        require(ancestry.get("status") in {"identical","ahead"},
                "package source commit not in current trusted main ancestry")
        manifest=pinned_json(source_commit,"config/extension.json")
        tc=pinned_json(source_commit,"config/test-contract.json")
        require(manifest["upstream"]["commit"]==pkg["upstream"]["commit"]
                and manifest["upstream"]["version"]==TAG.fullmatch(tag).group(1),
                "upstream manifest changed from release")
        original=json.loads(dest.read_text(encoding="utf-8"))
        modified=update_record(original,rel,manifest,tc,assets,sums,source_commit)
        if modified==original:
            print("NO_CHANGE: Catalog already matches verified Release")
            return False
        dest.write_text(json.dumps(modified,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({"status":"CATALOG_PR_READY","release":tag,"sourceCommit":source_commit,
                          "majors":[15,16,17,18]}))
        return True

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--extension",required=True)
    p.add_argument("--release-tag",required=True)
    p.add_argument("--output",required=True)
    a=p.parse_args()
    try:
        changed=generate(a.extension,a.release_tag,Path(a.output))
        output=os.environ.get("GITHUB_OUTPUT")
        if output:
            with open(output,"a",encoding="utf-8") as f:f.write("changed="+str(changed).lower()+"\n")
        return 0
    except (UnsafeCatalog, OSError, ValueError, KeyError, IndexError, TypeError) as error:
        print("CATALOG SYNC BLOCKED (no PR): "+str(error),file=sys.stderr)
        return 2

if __name__=="__main__":sys.exit(main())
