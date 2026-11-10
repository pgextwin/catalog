#!/usr/bin/env python3
"""Exact-path PGroonga 4.1.0 original ZIP rights triage; NEVER authorization."""
import argparse
import json
from pathlib import Path
import tempfile

from issue112_pgroonga_rights_audit import (
    PINS, audit_members, download_original, original_name,
)

# Exhaustive paths observed in five pinned official ZIPs, NOT trusted component
# identity. Pattern matching a file name to a license would be misleading.
PATH_GROUPS = {
    "pgroonga": (
        "lib/pgroonga.dll", "lib/pgroonga_check.dll",
        "lib/pgroonga_crash_safer.dll", "lib/pgroonga_database.dll",
        "lib/pgroonga_standby_maintainer.dll", "lib/pgroonga_wal_applier.dll",
        "lib/pgroonga_wal_resource_manager.dll",
    ),
    "groonga": (
        "bin/grndb.exe", "bin/groonga-suggest-create-dataset.exe",
        "bin/groonga.exe", "bin/libgroonga.dll",
        "lib/groonga/plugins/functions/binary.dll",
        "lib/groonga/plugins/functions/index_column.dll",
        "lib/groonga/plugins/functions/language_model.dll",
        "lib/groonga/plugins/functions/math.dll",
        "lib/groonga/plugins/functions/number.dll",
        "lib/groonga/plugins/functions/string.dll",
        "lib/groonga/plugins/functions/time.dll",
        "lib/groonga/plugins/functions/vector.dll",
        "lib/groonga/plugins/query_expanders/tsv.dll",
        "lib/groonga/plugins/suggest/suggest.dll",
        "lib/groonga/plugins/token_filters/stop_word.dll",
    ),
    "mecab": (
        "bin/libmecab.dll", "bin/mecab-dict-index.exe",
        "bin/mecab.exe", "lib/groonga/plugins/tokenizers/mecab.dll",
    ),
    "xxhash": ("bin/libxxhash.dll", "bin/xxhsum.exe"),
    "msgpack_c": ("bin/msgpack-c.dll",),
    "llama_ggml": (
        "bin/groonga-ggml-base.dll", "bin/groonga-ggml.dll",
        "bin/groonga-llama.dll",
        "lib/groonga/ggml/ggml-cpu-alderlake.dll",
        "lib/groonga/ggml/ggml-cpu-cannonlake.dll",
        "lib/groonga/ggml/ggml-cpu-cascadelake.dll",
        "lib/groonga/ggml/ggml-cpu-haswell.dll",
        "lib/groonga/ggml/ggml-cpu-icelake.dll",
        "lib/groonga/ggml/ggml-cpu-sandybridge.dll",
        "lib/groonga/ggml/ggml-cpu-skylakex.dll",
        "lib/groonga/ggml/ggml-cpu-sse42.dll",
        "lib/groonga/ggml/ggml-cpu-x64.dll",
    ),
    "h3": ("lib/groonga/plugins/functions/h3.dll",
           "lib/groonga/plugins/tokenizers/h3_index.dll"),
}

# Review hints only; never accepted component identity, licensing or provenance.
DOC_CANDIDATES = {
    "pgroonga": ("share/pgroonga/COPYING",),
    "groonga": ("share/groonga/COPYING",),
    "mecab": ("share/groonga/mecab/COPYING",),
    "xxhash": (),  # No xxHash-specific license among 20 captured documents.
    "msgpack_c": ("share/groonga/msgpack-c/COPYING",
                  "share/groonga/msgpack-c/LICENSE_1_0.txt",
                  "share/groonga/msgpack-c/NOTICE"),
    "llama_ggml": ("share/groonga/llama.cpp/LICENSE",),
    "h3": ("share/groonga/h3/LICENSE", "share/groonga/h3/NOTICE"),
}

PATH_TO_GROUP = {p: g for g, paths in PATH_GROUPS.items() for p in paths}
assert len(PATH_TO_GROUP) == sum(map(len, PATH_GROUPS.values())) == 43
assert set(PATH_GROUPS) == set(DOC_CANDIDATES)


def join_receipts(receipts, *, strict=False):
    """Return exhaustive, non-authorizing path-to-document review suggestions."""
    binaries = receipts["binaryMemberReceipts"]
    docs = receipts["licenseNoticeFiles"]
    binary_paths = [r["path"] for r in binaries]
    doc_paths = [r["path"] for r in docs]
    if len(binary_paths) != len(set(binary_paths)) or len(doc_paths) != len(set(doc_paths)):
        raise ValueError("Duplicate original member path in evidence")
    if strict and (set(binary_paths) != set(PATH_TO_GROUP)
                   or len(binary_paths) != 43 or len(docs) != 20):
        raise ValueError("Exact 4.1.0 package inventory changed; re-audit, never infer rights")
    docs_by_path = {r["path"]: r for r in docs}
    result = []
    linked_docs = set()
    for row in sorted(binaries, key=lambda r: r["path"]):
        group = PATH_TO_GROUP.get(row["path"])
        expected_docs = DOC_CANDIDATES[group] if group else ()
        observed = [docs_by_path[p] for p in expected_docs if p in docs_by_path]
        linked_docs.update(d["path"] for d in observed)
        result.append({
            "path": row["path"], "bytes": row["bytes"], "sha256": row["sha256"],
            "candidateComponentGroup": group,
            "candidateDocuments": [
                {"path": d["path"], "sha256": d["sha256"]} for d in observed
            ],
            "missingExpectedCandidateDocuments": sorted(
                set(expected_docs) - set(docs_by_path)
            ),
            "exactComponentVersionVerified": False,
            "componentLicenseNoticeVerified": False,
            "sourceToBinaryProvenanceVerified": False,
            "candidateAssociationIsLegalAcceptance": False,
        })
    return {
        "schemaVersion": "pgextwin-pgroonga-rights-join-nonpublishing/v1",
        "pgMajor": receipts["pgMajor"], "version": receipts["version"],
        "originalZipSha256": receipts["expectedZipSha256"],
        "binaryCount": len(result), "documentCount": len(docs),
        "pathIdentityCoverage": sum(x["candidateComponentGroup"] is not None for x in result),
        "binaryWithoutNamedDocumentCandidateCount": sum(
            not x["candidateDocuments"] for x in result),
        "documentsNotLinkedByBinaryNameTriage": sorted(set(doc_paths) - linked_docs),
        "binaryRightsReviewRows": result,
        "allComponentVersionsVerified": False,
        "perBinaryLegalAcceptanceComplete": False,
        "sourceToBinaryProvenanceVerified": False,
        "independentSignedGetAdmission": False,
        "publicGetAuthorized": False,
        "mirrorAuthorized": False,
        "publisherAuthorized": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pg", type=int, choices=tuple(PINS), required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="pgroonga-rights-join-") as folder:
        target = Path(folder) / original_name(args.pg)
        download_original(args.pg, target)
        receipts = audit_members(target, args.pg)
        result = join_receipts(receipts, strict=True)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    print("RIGHTS_CANDIDATES_ONLY=YES COMPONENT_VERSIONS=UNVERIFIED "
          "PUBLISH=DENY PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
