#!/usr/bin/env python3
"""Issue #112 append-only SHA-sealed ORIGINAL five-row genuine diagnostic witness.

This tool verifies immutable archive byte provenance/receipt consistency, NOT
fresh cryptography: original gh/TUF dual-Sigstore was independently executed on
protected Catalog main Run 39001953632. Admission and distribution stay DENY.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile, BadZipFile

from distribution_manifest_v1 import Denied, require, strict_json, verify_archive_members
from distribution_release_verify_p1 import sha
from distribution_p1_plpgsql_event_recovery import (
    RELEASE_ID, PACKAGING, RUN_ID, PUBLISH_JOB, SIGNER,
    PG_ZIPS, ORIGINAL_JOBS, BUILD_ARTIFACTS, verify_protected_capture,
)

ROOT=Path(__file__).resolve().parents[1]
WITNESS=ROOT/"evidence/p1/plpgsql-five-original-crypto-observation-v1.json"
ARTIFACT_SHA="d0d03a2502c77f150d3179be166816fc0b31aa0d65ed26564e657dcd060662c8"
REPORT_SHA="48d322804fbd7870ffa28fdfcb76ea1faa9b6992b607c54384d8245500019cb4"
ARTIFACT_ID=12089781246
AUDIT_RUN=39001953632
AUDIT_JOB=117306569520
CATALOG_SHA="bd5b3fbe8d539e921006bb178b5c3d1d703ff5fc"
ENTRY="issue112-plpgsql-original-recovery-observation.json"
BUNDLES={
    14:"0f6d52b1e7076a6fdff4775d19577ed581f4be0b81aa88c092c93ba471f60f85",
    15:"ea64e1d63009ae27a7e8f8a12282aa6f4dd819e144bc63502a8d67e4a6ea4869",
    16:"5eacf0ca5c2cb6b48d88716796af55b40cab9530fe3b16b2e044ac58b5a5aeb7",
    17:"d98c5f3381411cba1fe576590621c16808c6fd3e441cf0edfaeebd0c59582a5d",
    18:"5c47eb36c8aca8c61d098e892bb4836add418c32db5dfb7a2e0e4dfe0ab3e56b",
}
SPDX={
    14:"33398d92d387ffc74c68ae7f6c84e4b9d99b546e94fd0a43daa2e90e3bee945f",
    15:"c91a41b36d63eb1c36e53a4265c62c801f535d2520a12220be8b42785bb66104",
    16:"1a58c1b095ef3b3bee5e98f5def04bdb85f3fc73e66fa8acbfeda21ef53c054a",
    17:"9b2d82cf08010ad23b6e9aeee625c7a47b8e2fa3cd9fc0c92e516f2488507345",
    18:"2d121aa0de6d15772ee20dcafa88a8850d0947a1ea92779bdda539542bad9d78",
}
GRYPE={
    14:"9aca1711fc2028c5d1337154b3a6780b29604f12b27b269ec2165ac4768f3e98",
    15:"a7541c86951b61dc41212f18b55c368376a41ffc9d418aadf9cfba09fee9f54e",
    16:"9539ec6b34b5f2a365baf5c61f482b8d159caea1c1833149682fdc607d8251bd",
    17:"b549b9cdb2e05afe1e0d8abdf1bc974e852ad075576606738fece403eab86a11",
    18:"1374756ac4196fd3f40ffe5f99aadd9fbea82c18b6bbfb1ed601f0dc555afaa2",
}
ASSET_IDS={14:630346386,15:630346404,16:630346414,17:630346427,18:630346436}
GH_SHA="7469124f706944133d6a169691dd1c6c3511b12e85878d255e044e2948df4c9b"
TUF_SHA="65ca537f6ed8a47fd0e560c421baa1f6c1efb8b25fc200d8c5c02c0e92eb2b9c"
EVENT_SHA="bed069a8ffe16f6cc3756a2e7608b84ecb9ababccad28d93c5e1c01889c643a8"


def expected_rows():
    return [{"pgMajor":pg,"originalBuildArtifactId":BUILD_ARTIFACTS[pg][0],
             "originalBuildJobId":ORIGINAL_JOBS[pg],"publicZipAssetId":ASSET_IDS[pg],
             "publicZipSha256":PG_ZIPS[pg],"publicSpdxSha256":SPDX[pg],
             "publicGrypeSha256":GRYPE[pg],"signedBundleSha256":BUNDLES[pg]}
            for pg in sorted(PG_ZIPS)]


def witness_validate(data):
    """Expected facts are hard-pinned code, not caller-provided JSON authority."""
    require(type(data) is dict
            and data.get("schema")=="pgextwin-plpgsql-original-five-crypto-observation/v1"
            and data.get("status")=="GENUINE_FIVE_PG_TECHNICALLY_VERIFIED_CAUSAL_BRIDGE_MISSING"
            and data.get("sourceProtectedMainSha")==CATALOG_SHA
            and data.get("sourceReadOnlyRunId")==AUDIT_RUN
            and data.get("sourceReadOnlyJobId")==AUDIT_JOB
            and data.get("sourceDiagnosticArtifactId")==ARTIFACT_ID
            and data.get("sourceDiagnosticArtifactArchiveBytes")==1808
            and data.get("sourceDiagnosticArtifactArchiveSha256")==ARTIFACT_SHA
            and data.get("sourceDiagnosticEntry")==ENTRY
            and data.get("sourceDiagnosticEntryBytes")==4775
            and data.get("sourceDiagnosticEntrySha256")==REPORT_SHA
            and data.get("pinnedCanonicalEventSha256")==EVENT_SHA
            and data.get("officialGhSha256")==GH_SHA
            and data.get("trustedRootSha256")==TUF_SHA
            and data.get("repository")=="pgextwin/plpgsql_check"
            and data.get("repositoryId")==1410581312
            and data.get("releaseId")==RELEASE_ID
            and data.get("releaseTag")=="v2.10.14-windows.1"
            and data.get("packagingSha")==PACKAGING
            and data.get("originalRunId")==RUN_ID
            and data.get("originalRunAttempt")==1
            and data.get("originalRunConclusion")=="failure"
            and data.get("originalPublishJobId")==PUBLISH_JOB
            and data.get("originalPublishJobConclusion")=="failure"
            and data.get("originalAuthorizeJobId")==114436691584
            and data.get("originalAuthorizeJobConclusion")=="success"
            and data.get("verifiedReleaseOriginalAssetCount")==16
            and data.get("originalBuildArtifactMemberCount")==15
            and data.get("originalDualSignatureVerifiedCount")==5
            and data.get("pgRows")==expected_rows()
            and data.get("eventPublishingToken") is None
            and data.get("eventPublishingHttpMethod") is None
            and data.get("manualApprovalToPublishedEventCausalityVerified") is False
            and data.get("formalP1Accepted")==65
            and data.get("formalP1Total")==70
            and data.get("historicalSourceFormalAccepted")==40
            and data.get("p1")=="BLOCKED" and data.get("p2")=="NO-GO"
            and data.get("publicationAuthorized") is False
            and data.get("distributionAuthorized") is False
            and data.get("formalDistribution")=="DENY",
            "untrusted or escalated original five-PG observation witness")
    verify_protected_capture()
    return data


def report_validate(report, witness):
    """Only independently SHA-sealed real diagnostic rows; still NOT admission."""
    require(type(report) is dict
            and report.get("schema")=="pgextwin-plpgsql-original-recovery-diagnostic/v1"
            and report.get("status")=="OBSERVATION_ONLY_NOT_FORMAL_ACCEPTANCE"
            and report.get("officialGhSha256")==GH_SHA
            and report.get("trustedRootSha256")==TUF_SHA
            and report.get("eventCanonicalSha256")==EVENT_SHA
            and report.get("releaseId")==RELEASE_ID
            and report.get("releaseAssetCount")==16
            and report.get("runId")==RUN_ID
            and report.get("runAttempt")==1
            and report.get("runConclusion")=="failure"
            and report.get("publishJobConclusion")=="failure"
            and report.get("verifiedPgCount")==5
            and type(report.get("pgResults")) is dict
            and set(report["pgResults"])=={"14","15","16","17","18"}
            and report.get("causalBridgeIndependentlyVerified") is False
            and report.get("publicationAuthorized") is False
            and report.get("distributionAuthorized") is False
            and report.get("p1FormalAccepted")==65
            and report.get("historicalSourceFormalAccepted")==40,
            "diagnostic claimed unearned acceptance or changed original run")
    for expected in witness["pgRows"]:
        pg=expected["pgMajor"]
        row=report["pgResults"][str(pg)]
        base=f"plpgsql_check-v2.10.14-pg{pg}-windows-x64"
        require(type(row) is dict
                and row.get("genuineDualSigstore") is True
                and row.get("originalBuildArtifactId")==BUILD_ARTIFACTS[pg][0]
                and row.get("originalBuildJobId")==ORIGINAL_JOBS[pg]
                and row.get("publishedZipAssetId")==ASSET_IDS[pg]
                and row.get("publishedZipSha256")==PG_ZIPS[pg]
                and row.get("bundleSha256")==BUNDLES[pg]
                and row.get("originalInnerHashes")=={
                    base+".zip":PG_ZIPS[pg],
                    base+".spdx.json":SPDX[pg],
                    base+".vulnerabilities.json":GRYPE[pg]},
                "wrong original PG artifacts/Sigstore bundle/Release SHA")
    return True


def validate_archived_diagnostic(path):
    """Read immutable GitHub Actions diagnostic ZIP; never a Release/attestation."""
    require(path.is_file() and not path.is_symlink()
            and path.stat().st_size==1808 and sha(path)==ARTIFACT_SHA,
            "BLOCKED: original protected-main diagnostic Artifact bytes missing/swapped")
    try:
        with ZipFile(path) as z:
            verify_archive_members(z)
            require(z.namelist()==[ENTRY] and z.getinfo(ENTRY).file_size==4775,
                    "malformed original diagnostic archive")
            report=z.read(ENTRY)
        require(hashlib.sha256(report).hexdigest()==REPORT_SHA,
                "changed archived original diagnostic JSON SHA")
        observed=strict_json(report)
    except (BadZipFile,OSError,ValueError,RuntimeError,KeyError) as exc:
        raise Denied("BLOCKED: original diagnostic artifact malformed") from exc
    witness=witness_validate(strict_json(WITNESS.read_bytes()))
    report_validate(observed,witness)
    return {"type":"ORIGINAL_PROTECTED_MAIN_OBSERVATION_ONLY",
            "archivedDiagnosticSha256":ARTIFACT_SHA,"reportSha256":REPORT_SHA,
            "genuineOriginalPgCandidates":5,"formalNewAccepted":0,
            "originalRunConclusion":"failure","originalPublishJobConclusion":"failure",
            "causalBridgeIndependentlyVerified":False,
            "publicationAuthorized":False,"distributionAuthorized":False}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--original-audit-zip",type=Path)
    args=ap.parse_args()
    if args.original_audit_zip:
        report=validate_archived_diagnostic(args.original_audit_zip)
    else:
        witness_validate(strict_json(WITNESS.read_bytes()))
        report={"type":"SEALED_WITNESS_METADATA_ONLY_NOT_FRESH_CRYPTO",
                "genuineOriginalPgCandidates":5,"formalNewAccepted":0,
                "publicationAuthorized":False,"distributionAuthorized":False}
    print(json.dumps(report,sort_keys=True))


if __name__=="__main__":
    try:main()
    except (Denied,OSError,TypeError,ValueError,KeyError) as exc:
        raise SystemExit("DENY: "+str(exc)) from exc
