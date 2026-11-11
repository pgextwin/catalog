#!/usr/bin/env python3
"""Select previously rehashed OSGeo PG14-17 originals for isolated Windows SQL.

This deliberately consumes candidate-only directory metadata, not public trust
or Publisher admission. SHA256 values are previous independent observations.
"""
import argparse
import json
from pathlib import Path
from issue112_osgeo_pg14_17_static_review import select

def make_selection(snapshot, pg):
    row = select(snapshot, str(pg))
    return {
        "status": "CANDIDATE_ONLY",
        **row,
        "windowsSqlRuntimeVerified": False,
        "dynamicDependenciesVerified": False,
        "allComponentNoticesVerified": False,
        "producerProvenanceVerified": False,
        "independentSignatureVerified": False,
        "publicGetAuthorized": False,
        "mirrorAuthorized": False,
        "publisherAuthorized": False,
        "releaseAuthorized": False,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection-file", type=Path, required=True)
    parser.add_argument("--pg-major", choices=("14", "15", "16", "17"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshot = json.loads(args.selection_file.read_text(encoding="utf-8"))
    row = make_selection(snapshot, args.pg_major)
    args.output.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
    print("OSGEO_CANDIDATE_SELECTION=PASS PG=" + args.pg_major +
          " PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")

if __name__ == "__main__":
    main()
