#!/usr/bin/env python3
"""Compare two unsigned Catalog feeds by canonical payload.

Two feeds built at different Catalog commits differ in the root
``catalogCommit`` and in the latest Release admission of every extension
(both name the build commit).  Those are the only source-SHA fields a
format-only rewrite may change.  This comparator asserts that shape,
substitutes one common SHA for exactly those fields in comparison copies,
and compares the entire canonical byte streams.  Historical admissions,
array order, policy fields and package fields are compared verbatim.

Exit codes: 0 = canonical payloads equal, 1 = different, 2 = error
(unbuildable feed or a payload that does not name its own checkout).
Used by the signed-feed publication gate (a format-only change must not
mint a new feed) and by the proposal-C C3 migration comparison.
"""
import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

if __package__:
    from . import cli_signed_feed as feed_builder
else:
    import cli_signed_feed as feed_builder

PLACEHOLDER = "0" * 40


def assert_own_checkout(feed, commit):
    """The payload must name its own checkout at the root and at the
    unique latest Release admission of every extension."""
    if feed.get("catalogCommit") != commit:
        raise ValueError("Feed root does not name its own checkout commit")
    for extension in feed["extensions"]:
        latest = [row for row in extension["releases"]
                  if row["admission"].get("catalogCommit") == commit]
        if len(latest) != 1 or latest[0]["releaseTag"] != extension["latestReleaseTag"]:
            raise ValueError(
                f"{extension['extension']}: latest Release admission does not "
                "uniquely name the checkout commit")


def normalized(feed, commit):
    """Comparison copy with the root and latest-admission SHAs replaced
    by one common placeholder.  The input feed is not modified."""
    assert_own_checkout(feed, commit)
    result = copy.deepcopy(feed)
    result["catalogCommit"] = PLACEHOLDER
    for extension in result["extensions"]:
        for row in extension["releases"]:
            if row["admission"].get("catalogCommit") == commit:
                row["admission"]["catalogCommit"] = PLACEHOLDER
    return result


def normalized_bytes(feed, commit):
    return feed_builder.canonical(normalized(feed, commit))


def compare(root_a, commit_a, root_b, commit_b):
    """Return (equal, raw_a, raw_b, normalized_a, normalized_b) digests."""
    feed_a = feed_builder.build_feed(root_a, commit_a)
    feed_b = feed_builder.build_feed(root_b, commit_b)
    raw_a = hashlib.sha256(feed_builder.canonical(feed_a)).hexdigest()
    raw_b = hashlib.sha256(feed_builder.canonical(feed_b)).hexdigest()
    norm_a = hashlib.sha256(normalized_bytes(feed_a, commit_a)).hexdigest()
    norm_b = hashlib.sha256(normalized_bytes(feed_b, commit_b)).hexdigest()
    return norm_a == norm_b, raw_a, raw_b, norm_a, norm_b


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog-a", required=True)
    parser.add_argument("--commit-a", required=True)
    parser.add_argument("--catalog-b", required=True)
    parser.add_argument("--commit-b", required=True)
    opts = parser.parse_args()
    try:
        equal, raw_a, raw_b, norm_a, norm_b = compare(
            Path(opts.catalog_a), opts.commit_a, Path(opts.catalog_b), opts.commit_b)
    except Exception as exc:  # build or shape failure: not a comparison result
        print(f"CATALOG_FEED_COMPARE_ERROR={exc}")
        return 2
    print(f"CATALOG_FEED_RAW_SHA256_A={raw_a}")
    print(f"CATALOG_FEED_RAW_SHA256_B={raw_b}")
    print(f"CATALOG_FEED_NORMALIZED_SHA256_A={norm_a}")
    print(f"CATALOG_FEED_NORMALIZED_SHA256_B={norm_b}")
    print("CATALOG_FEED_CANONICAL_MATCH" if equal else "CATALOG_FEED_CANONICAL_DIFF")
    return 0 if equal else 1


if __name__ == "__main__":
    sys.exit(main())
