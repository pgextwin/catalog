#!/usr/bin/env python3
"""Issue #112: inspect two exact original-provider links without promoting trust.

This review is not an authenticated signed feed, a download pin, a legal
opinion, a Publisher approval, a mirror license, or a CLI download adapter.
"""
import json
from pathlib import Path
from urllib.parse import urlparse

from external_admission_preflight import ROOT, PILOT, identity, load_candidates, pilot_index, read_json

REVIEW = "evidence/issue112-external-pg18-direct-link-review-v1.json"
SCHEMA = "pgextwin-external-original-link-review/v1"
EXACT_ASSETS = {
    ("laurenz/oracle_fdw", 335861225, 442625860):
        ("oracle_fdw", "2.9.0", "18", "upstream-official", 14332609, 365101),
    ("andreiramani/pgvector_pgsql_windows", 419235203, 661612613):
        ("pgvector", "0.8.7", "18", "community", 838202416, 174796),
}
FALSE_FLAGS = (
    "publicationAuthorized", "downloadAuthorized", "mirrorAuthorized",
    "redistributionAuthorized", "signedExternalCatalogPin",
)


def strict_read(path):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate direct-link review key: " + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)


def https_url(url, host, path):
    if not isinstance(url, str):
        return False
    parsed = urlparse(url)
    return (parsed.scheme == "https" and parsed.netloc == host
            and parsed.path == path and not parsed.query and not parsed.fragment
            and not parsed.username and not parsed.password
            and parsed.geturl() == url)


def validate_review(root=ROOT, review=None):
    root = Path(root)
    doc = strict_read(root / REVIEW) if review is None else review
    if (doc.get("schemaVersion") != SCHEMA
            or doc.get("scope") != "REFERENCE_TO_UNMODIFIED_PROVIDER_RELEASE_ASSET_ONLY"
            or doc.get("rightsReview") != "SOURCE_AND_NOTICE_REFERENCES_REVIEWED_NOT_DISTRIBUTION_APPROVAL"
            or any(doc.get(flag) is not False for flag in FALSE_FLAGS)):
        raise ValueError("Direct-link review is not an authority source")
    values = doc.get("records")
    if not isinstance(values, list) or len(values) != len(EXACT_ASSETS):
        raise ValueError("Review must be restricted to two exact PG18 pilots")

    candidates = load_candidates(root)
    candidate_index = {identity(c): c for c in candidates}
    if len(candidates) != 203 or len(candidate_index) != len(candidates):
        raise ValueError("Discovery snapshot unexpectedly changed")
    pilot = read_json(root / PILOT)
    original_hashes = pilot_index(pilot, candidates)
    seen = set()
    for item in values:
        if not isinstance(item, dict):
            raise ValueError("Invalid reviewed asset")
        key = (item.get("sourceRepo"), item.get("releaseId"), item.get("assetId"))
        if key not in EXACT_ASSETS or key in seen or key not in original_hashes:
            raise ValueError("Unknown, repeated or unverified original asset")
        seen.add(key)
        c = candidate_index[key]
        extension, version, major, provider_type, repo_id, size = EXACT_ASSETS[key]
        for field, expected in (
            ("extension", extension), ("upstreamVersion", version),
            ("pgMajor", major), ("providerType", provider_type),
            ("repositoryId", repo_id), ("originalBytes", size),
            ("originalSha256", original_hashes[key]),
            ("releaseTag", c["releaseTag"]), ("assetName", c["assetName"]),
            ("originalProviderUrl", c["assetUrl"]),
        ):
            if item.get(field) != expected:
                raise ValueError("Original-provider review asset binding mismatch: " + field)
        if not https_url(item["originalProviderUrl"], "github.com",
                         f"/{key[0]}/releases/download/{c['releaseTag']}/{c['assetName']}"):
            raise ValueError("Unapproved direct-link host, path or query")
        if (item.get("referenceLinkReviewed") is not True
                or any(item.get(flag) is not False for flag in
                       ("downloadAuthorized", "mirrorAuthorized", "mirrorRightsReviewed"))
                or not isinstance(item.get("noticeTreatment"), str)
                or len(item["noticeTreatment"]) < 100
                or not isinstance(item.get("providerStatusNotice"), str)
                or len(item["providerStatusNotice"]) < 25
                or item.get("targetEnvironment") != "EDB PostgreSQL 18.6.5 Windows x64"):
            raise ValueError("Missing NOTICE, target or restricted-link decision")
        if key[0] == "laurenz/oracle_fdw":
            links = (
                ("packageLicenseUrl", "github.com", "/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/LICENSE"),
                ("dependencyInformationUrl", "github.com", "/laurenz/oracle_fdw/blob/ORACLE_FDW_2_9_0/README.oracle_fdw"),
                ("dependencyLicenseUrl", "www.oracle.com", "/downloads/licenses/instant-client-lic.html"),
                ("runtimeEvidence", "github.com", "/pgextwin/catalog/actions/runs/41661506504"),
            )
            if item.get("runtimeScope") != "CREATE_EXTENSION_AND_ORACLE_DIAG_ONLY_NO_REMOTE_DATABASE":
                raise ValueError("Oracle evidence scope changed")
        else:
            links = (
                ("packageLicenseUrl", "github.com", "/pgvector/pgvector/blob/v0.8.7/LICENSE"),
                ("dependencyInformationUrl", "github.com", "/andreiramani/pgvector_pgsql_windows/blob/main/README.md"),
                ("runtimeEvidence", "github.com", "/pgextwin/catalog/actions/runs/41657903202"),
            )
            if (item.get("dependencyLicenseUrl") is not None
                    or item.get("runtimeScope") != "CREATE_EXTENSION_VERSION_AND_SQL_DISTANCE_OPERATOR_ONLY"
                    or "Unofficial" not in item["providerStatusNotice"]):
                raise ValueError("Unofficial pgvector identity/notice changed")
        if any(not https_url(item.get(field), host, path) for field, host, path in links):
            raise ValueError("Missing or moved original license/runtime reference")
        if (c["downloadAuthorized"] is not False or c["rightsReviewed"] is not False
                or c["redistributionAuthorization"] != "not-authorized"):
            raise ValueError("Discovery metadata attempted authority promotion")
    if seen != set(EXACT_ASSETS):
        raise ValueError("Missing exact reviewed provider")
    return {
        "referenceLinksReviewed": len(seen),
        "signedExternalCatalogPins": 0,
        "downloadAuthorized": False,
        "mirrorAuthorized": False,
        "scope": "CANDIDATE_ONLY",
    }


if __name__ == "__main__":
    print(json.dumps(validate_review(), sort_keys=True))
