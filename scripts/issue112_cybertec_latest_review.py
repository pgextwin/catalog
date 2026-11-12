#!/usr/bin/env python3
"""Offline source-label selection from untrusted Cybertec HTML index receipts.

No ZIP GET, upstream-version claim, compatibility acceptance or publishing.
The existing index parser owns canonical-source GET and hostile HTML checks.
"""
import argparse
import json
import re

from issue112_cybertec_windows_index import BASE, MAJORS, collect, fetch_index

EXTENSION = re.compile(r"[a-z][a-z0-9_]{1,40}\Z")
LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,110}\Z")
NUMERIC_LABEL = re.compile(
    r"(?:v|VERSION_|REL_?|)?(?P<digits>\d+(?:[._]\d+){1,3})"
    r"(?:-\d+(?:-g[0-9a-fA-F]{5,40})?(?:-\d+)?)?\Z"
)
DENIED = (
    "originalBytesVerified", "originalSha256Verified", "upstreamVersionVerified",
    "communityPostgresqlAbiVerified", "producerProvenanceVerified",
    "licenseNoticeClosureVerified", "independentSignedAdmission",
    "publicGetAuthorized", "mirrorAuthorized", "publisherAuthorized",
    "releaseAuthorized",
)


def label_rank(label, major):
    """Rank untrusted numeric packaging labels, never upstream versions.

    REL17_1_7_1 encodes PG17 as a prefix; remove it only for that PG.
    Unparseable labels return None rather than receiving an invented order.
    """
    match = NUMERIC_LABEL.fullmatch(label)
    if match is None:
        return None
    parts = tuple(int(v) for v in re.split(r"[._]", match.group("digits")))
    if label.startswith("REL") and len(parts) == 4 and parts[0] == int(major):
        parts = parts[1:]
    return parts + (0,) * (4 - len(parts))


def review(report, *, extension=None, label=None, latest_only=False):
    """Validate every row before filtering; never mask an unrelated poison."""
    if extension is not None and not EXTENSION.fullmatch(extension):
        raise ValueError("Invalid extension selector")
    if label is not None and (extension is None or not LABEL.fullmatch(label)):
        raise ValueError("Exact packaging label requires a valid extension")
    if type(report) is not dict or report.get("schemaVersion") != (
            "pgextwin-issue112-cybertec-windows-index/v1") or (
            report.get("origin") != BASE or
            report.get("trust") != "UNTRUSTED_DIRECTORY_METADATA_ONLY" or
            report.get("latestVersionResolution") != "NOT_VERIFIED"):
        raise ValueError("Input must be the original non-authorizing index receipt")
    if any(report.get(flag) is not False for flag in (
            "publicGetAuthorized", "mirrorAuthorized", "publisherAuthorized",
            "releaseAuthorized", "sourceArchiveDownloaded", "binaryArchiveDownloaded")):
        raise ValueError("Unexpected root trust escalation")
    rows = report.get("candidates")
    majors = report.get("pgMajorsObserved")
    if (type(rows) is not list or not rows or type(majors) is not list or
            not majors or len(majors) != len(set(majors)) or
            any(major not in MAJORS for major in majors) or
            report.get("zipCandidates") != len(rows)):
        raise ValueError("Invalid canonical index cohort")
    unique = set()
    by_group = {}
    for item in rows:
        if type(item) is not dict or set(item) != {
                "extension", "pgMajor", "providerBuildLabelUntrusted", "fileName",
                "originalUrlUntrusted", *DENIED}:
            raise ValueError("Unexpected candidate fields")
        ext, pg, lbl, name = (item["extension"], item["pgMajor"],
                              item["providerBuildLabelUntrusted"], item["fileName"])
        if (type(ext) is not str or not EXTENSION.fullmatch(ext) or
                pg not in majors or type(lbl) is not str or not LABEL.fullmatch(lbl) or
                type(name) is not str or name not in (
                    f"{ext}-{pg}-public-{lbl}.zip", f"{ext}-{pg}-{pg}-public-{lbl}.zip") or
                item["originalUrlUntrusted"] != BASE + pg + "/extension/" + name or
                any(item[flag] is not False for flag in DENIED)):
            raise ValueError("Candidate identity or authority drift")
        key = (pg, name.casefold())
        if key in unique:
            raise ValueError("Duplicate source candidate")
        unique.add(key)
        by_group.setdefault((ext, pg), []).append(item)
    chosen = []
    unresolved = []
    for key, group in sorted(by_group.items()):
        if extension is not None and key[0] != extension:
            continue
        if latest_only:
            scored = [(label_rank(x["providerBuildLabelUntrusted"], key[1]), x)
                      for x in group]
            if any(score is None for score, _ in scored):
                unresolved.append({"extension": key[0], "pgMajor": key[1],
                                   "reason": "UNRANKABLE_PROVIDER_LABEL"})
                continue
            top = max(score for score, _ in scored)
            group = [x for score, x in scored if score == top]
        if label is not None:
            group = [x for x in group if x["providerBuildLabelUntrusted"] == label]
        chosen.extend(group)
    return {
        "schemaVersion": "pgextwin-issue112-cybertec-observed-review/v1",
        "trust": "UNTRUSTED_SOURCE_LABELS_ONLY_NOT_UPSTREAM_LATEST",
        "pgMajorsObserved": majors, "requestedExtension": extension,
        "requestedPackagingLabel": label,
        "selection": "MAX_NUMERIC_PROVIDER_LABEL_PER_EXTENSION_PG" if latest_only else "ALL_OBSERVED_LABELS",
        "unrankableGroups": unresolved,
        "observedCandidateCount": len(chosen),
        "latestUpstreamVersionVerified": False,
        "communityPostgresqlAbiVerified": False,
        "originalBytesVerified": False,
        "independentSignedAdmission": False,
        "publicGetAuthorized": False, "mirrorAuthorized": False,
        "releaseAuthorized": False, "publisherAuthorized": False,
        "candidates": chosen,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg", choices=MAJORS,
                        help="Index major (default: all PG14-18; missing index is fatal)")
    parser.add_argument("--extension", help="Exact extension name")
    parser.add_argument("--label", help="Exact provider packaging label, not upstream --version")
    parser.add_argument("--latest-observed", action="store_true",
                        help="Highest numeric observed label per extension/PG, not verified latest")
    opts = parser.parse_args()
    indexes = {m: fetch_index(m) for m in ((opts.pg,) if opts.pg else MAJORS)}
    result = review(collect(indexes), extension=opts.extension,
                    label=opts.label, latest_only=opts.latest_observed)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    print("CYBERTEC_LABEL_REVIEW=NONPUBLISHING LATEST_UPSTREAM=UNVERIFIED "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
