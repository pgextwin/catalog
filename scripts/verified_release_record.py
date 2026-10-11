#!/usr/bin/env python3
"""Pure, fail-closed Catalog v2 mapping for 14 pgextwin signed public Releases.

Does not download artifacts, verify GitHub attestations, dispatch workflows,
merge PRs or publish Releases. Call ONLY after a separate fully signed Release
verifier has checked actual remote asset bytes and provenance.
"""
from __future__ import annotations
import copy
import re

ALLOWED = {
    "pg_bigm": "pgbigm/pg_bigm",
    "pg_cron": "citusdata/pg_cron",
    "pg_hint_plan": "ossc-db/pg_hint_plan",
    "pgaudit": "pgaudit/pgaudit",
    "set_user": "pgaudit/set_user",
    "pg_repack": "reorg/pg_repack",
    "pg_ivm": "sraoss/pg_ivm",
    "pg_qualstats": "powa-team/pg_qualstats",
    "plpgsql_check": "okbob/plpgsql_check",
    "hypopg": "HypoPG/hypopg",
    "wal2json": "eulerto/wal2json",
    "pg_partman": "pgpartman/pg_partman",
    "pg_stat_monitor": "percona/pg_stat_monitor",
    "orafce": "orafce/orafce",
}
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SEMVER = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
RUN = re.compile(r"^[1-9][0-9]*$")
SUFFIXES = (".zip", ".spdx.json", ".vulnerabilities.json")

class Denied(ValueError):
    pass

def require(test, why):
    if not test:
        raise Denied(why)

def majors(ext):
    p=ext.get("postgresql",{})
    if isinstance(p.get("majors"),list):
        nums=p["majors"]
    else:
        lo,hi=p.get("minMajor"),p.get("maxMajor")
        require(type(lo) is int and type(hi) is int and lo<=hi,
                "invalid PG major range")
        nums=list(range(lo,hi+1))
    require(bool(nums) and all(type(n) is int and n in range(14,19) for n in nums)
            and nums==sorted(set(nums)), "invalid PG major set")
    return nums

def source_map(ext):
    name=ext.get("name")
    require(isinstance(name,str) and name in ALLOWED
            and ext.get("upstream",{}).get("repository")==ALLOWED[name],
            "untrusted extension / upstream identity")
    upstream=ext["upstream"]
    allowed=majors(ext)
    series=upstream.get("perPostgresql")
    if series is not None:
        require(isinstance(series,dict) and set(series)=={str(m) for m in allowed},
                "incomplete per-major upstream set")
    src={}
    for m in allowed:
        o=series[str(m)] if series is not None else upstream
        require(isinstance(o,dict) and isinstance(o.get("ref"),str)
                and REF.fullmatch(o["ref"]) is not None
                and isinstance(o.get("version"),str)
                and SEMVER.fullmatch(o["version"]) is not None
                and isinstance(o.get("commit"),str)
                and SHA.fullmatch(o["commit"]) is not None,
                "missing pinned upstream identity for PG"+str(m))
        src[m]=o
    return src

def tag_for(ext, revision):
    require(isinstance(revision,str) and RUN.fullmatch(revision),
            "invalid create-only release revision")
    src=source_map(ext)
    latest=src[max(src)]
    if ext["name"]=="pg_bigm":
        stem=latest["ref"]
        require(re.fullmatch(r"v[0-9]+\.[0-9]+-[0-9]{8}",stem),
                "pg_bigm dated versioned tag missing")
    else:
        stem="v"+latest["version"]
    return stem+"-windows."+revision

def map_verified_release(existing, release, ext, contract, assets, sums,
                         source_commit, required_majors):
    """Record transformation only: caller independently proves signature/bytes."""
    require(isinstance(existing,dict) and isinstance(release,dict)
            and isinstance(ext,dict) and isinstance(contract,dict),
            "incomplete release mapping inputs")
    src=source_map(ext)
    name=ext["name"]
    repo="pgextwin/"+name
    require(existing.get("schemaVersion")==2 and existing.get("name")==name
            and existing.get("repository")==repo
            and existing.get("upstream",{}).get("repository")==ALLOWED[name],
            "catalog/upstream identity changed")
    require(contract.get("contractVersion")==2
            and contract.get("extension")==name
            and isinstance(contract.get("coverage"),dict)
            and isinstance(contract.get("functionalScenarios"),list)
            and isinstance(contract.get("runtimeRequirements"),dict),
            "invalid Test Contract v2 for extension")
    require(isinstance(source_commit,str) and SHA.fullmatch(source_commit),
            "unpinned packaging main SHA")
    tag=release.get("tag_name")
    require(isinstance(tag,str) and "-windows." in tag
            and tag==tag_for(ext,tag.rsplit("-windows.",1)[1]),
            "Release tag/version does not match pinned extension manifest")
    require(release.get("draft") is False and release.get("prerelease") is False
            and bool(release.get("published_at"))
            and release.get("target_commitish")==source_commit,
            "Release is unpublished or not at verified immutable source SHA")
    require(isinstance(required_majors,list)
            and bool(required_majors)
            and required_majors==sorted(set(required_majors))
            and set(required_majors).issubset(src),
            "release PG major coverage is incomplete or duplicate")
    require(isinstance(assets,dict) and isinstance(sums,dict),
            "missing exact signed asset/checksum input")
    expected={"SHA256SUMS.txt"}
    for major in required_majors:
        stem=name+"-"+src[major]["ref"]+"-pg"+str(major)+"-windows-x64"
        expected.update(stem+suf for suf in SUFFIXES)
    require(set(assets)==expected and set(sums)==expected-{"SHA256SUMS.txt"},
            "missing/extra signed ZIP, SPDX or Grype assets")
    for fn in expected-{"SHA256SUMS.txt"}:
        a=assets[fn]
        require(isinstance(a,dict) and a.get("name")==fn
                and a.get("state")=="uploaded"
                and isinstance(sums[fn],str)
                and DIGEST.fullmatch(sums[fn])
                and a.get("digest")=="sha256:"+sums[fn],
                "GitHub-hosted asset does not match exact SHA256: "+fn)
    check=assets["SHA256SUMS.txt"]
    require(check.get("name")=="SHA256SUMS.txt"
            and check.get("state")=="uploaded"
            and isinstance(check.get("digest"),str)
            and re.fullmatch(r"sha256:[a-f0-9]{64}",check["digest"]),
            "SHA256SUMS asset absent or has no GitHub SHA256")
    out=copy.deepcopy(existing)
    if "perPostgresql" in ext["upstream"]:
        out["upstream"]["perPostgresql"]={
            str(m):{"version":src[m]["version"],"ref":src[m]["ref"]}
            for m in sorted(src)}
    else:
        out["upstream"]["version"]=src[max(src)]["version"]
    out["latest"]={
        "releaseTag":tag,"publishedAt":release["published_at"],
        "releaseUrl":"https://github.com/"+repo+"/releases/tag/"+tag,
        "checksumsAsset":"SHA256SUMS.txt"
    }
    for m in required_majors:
        stem=name+"-"+src[m]["ref"]+"-pg"+str(m)+"-windows-x64"
        def entry(suffix):
            fn=stem+suffix
            return {"available":True,"asset":fn,
                    "downloadUrl":"https://github.com/"+repo+"/releases/download/"+tag+"/"+fn,
                    "sha256":sums[fn]}
        item=entry(".zip")
        item["evidence"]={
            "buildProvenanceAttestation":{"available":True},
            "sbom":entry(".spdx.json"),
            "sbomAttestation":{"available":True},
            "vulnerabilityReport":entry(".vulnerabilities.json")
        }
        out["postgresql"][str(m)]=item
    out["runtime"]["requirements"]=copy.deepcopy(contract["runtimeRequirements"])
    out["capabilities"]={
        "testContractVersion":2,
        "coverage":copy.deepcopy(contract["coverage"]),
        "functionalScenarios":copy.deepcopy(contract["functionalScenarios"])
    }
    out["capabilitiesSource"]={
        "repository":repo,
        "path":"config/test-contract.json",
        "commit":source_commit
    }
    return out
