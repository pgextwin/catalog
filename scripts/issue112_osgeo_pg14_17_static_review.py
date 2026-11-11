#!/usr/bin/env python3
"""OSGeo PG14-17 candidate-only static PE/rights evidence, no publication."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile
import zipfile

from issue112_osgeo_original_byte_pilot import choose_major, inspect, read_original
from issue112_osgeo_dependency_inventory import dependency_inventory, MAX_DLL_BYTES
from issue112_osgeo_rights_audit import MAX_LICENSE_BYTES

ORIGIN = "https://download-cache.osgeo.org/postgis/windows/"
# Exact observed PR original bytes: Run 42984575832. NOT distribution pins.
PINS = {
    "14": ("3.6.1", 124000548, "d95f1e0ed333c3b0729210fb6573d4d7e07bc7eba61868d51fb1eebd338b1a97"),
    "15": ("3.6.2", 123986945, "520c3fd7ebf95050d8d89dc1b626f4f43111a3d726f60b73bbbbbd95784688eb"),
    "16": ("3.6.2", 123957610, "9f4e8a30d69ed7cc0088dd3d218ac65bd4e26aa5b7bffcb2ebd7dcb74a4ff2a6"),
    "17": ("3.6.2", 123959035, "7ba180ee2a352987b9a2f194673652c59483b55852295ccf401dceccd8765425"),
}
LEGAL = re.compile(r"(?:^|[._-])(?:licen[cs]e|notice|copying|copyright)(?:$|[._-])", re.I)


def require(ok, why):
    if not ok:
        raise ValueError("OSGeo nonpublishing static review DENY: " + why)


def select(snapshot, pg):
    require(pg in PINS, "major outside observed scope")
    url, row = choose_major(snapshot, pg)
    version, size, sha = PINS[pg]
    name = f"postgis-bundle-pg{pg}-{version}x64.zip"
    require(url == f"{ORIGIN}pg{pg}/{name}" and row["fileName"] == name,
            "changed original version or host")
    return dict(pgMajor=pg, name=name, sourceUrl=url, version=version,
                expectedBytes=size, expectedSha256=sha)


def member_receipts(path, name):
    """Inspect exact DLL/legal member bytes; never assign licenses to DLLs."""
    root = name[:-4] + "/"
    required = {root + "LICENSE", root + "bin/COPYING",
                root + "gdal-data/LICENSE.TXT"}
    dlls, notices = [], []
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            dll = entry.filename.lower().endswith(".dll")
            legal = bool(LEGAL.search(entry.filename.rsplit("/", 1)[-1]))
            if not (dll or legal):
                continue
            limit = MAX_DLL_BYTES if dll else MAX_LICENSE_BYTES
            require(0 < entry.file_size <= limit, "invalid member size")
            digest, count = hashlib.sha256(), 0
            with archive.open(entry) as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    count += len(chunk)
                    require(count <= entry.file_size, "member exceeds declared size")
                    digest.update(chunk)
            require(count == entry.file_size, "truncated member")
            record = dict(path=entry.filename, bytes=count, sha256=digest.hexdigest())
            if dll:
                record["componentLicenseVerified"] = False
                record["producerProvenanceVerified"] = False
                dlls.append(record)
            else:
                notices.append(record)
    require(required <= {x["path"] for x in notices}, "missing expected legal files")
    require(any(x["path"].lower().endswith("/postgis-3.dll") for x in dlls),
            "PostGIS native DLL absent")
    require(any(re.search(r"/libpgrouting-[0-9.]+\.dll$", x["path"], re.I)
                for x in dlls), "pgRouting native DLL absent")
    return sorted(dlls, key=lambda x: x["path"]), sorted(notices, key=lambda x: x["path"])


def run(snapshot, pg):
    pin = select(snapshot, pg)
    with tempfile.TemporaryDirectory(prefix="osgeo-static-review-") as folder:
        original = Path(folder) / pin["name"]
        size, digest = read_original(pin["sourceUrl"], original)
        require((size, digest) == (pin["expectedBytes"], pin["expectedSha256"]),
                "observed original size/SHA256 mismatch")
        structure = inspect(original)
        dlls, notices = member_receipts(original, pin["name"])
        graph = dependency_inventory(original)
        require(graph["dllCount"] == len(dlls), "PE and original DLL count differ")
    # Existing graph helper has PG18 default labels; only reuse source-neutral
    # graph fields, with explicitly checked PG14-17 receipt above.
    result = {"status": "CANDIDATE_ONLY", **pin, "measuredBytes": size,
              "measuredSha256": digest, "zipMembers": structure["zipMembers"],
              "dllMemberReceipts": dlls, "legalMemberReceipts": notices,
              "parsedPeCount": graph["parsedPeCount"],
              "nonParsed": graph["nonParsed"],
              "importTriage": graph["unbundledImportTriage"],
              "serverGraph": graph["coreServerImportPaths"],
              "dllImports": graph["dllImports"],
              "allComponentNoticesVerified": False,
              "dynamicDependenciesVerified": False,
              "windowsSqlRuntimeVerified": False,
              "producerProvenanceVerified": False,
              "independentSignatureVerified": False,
              "publicGetAuthorized": False, "mirrorAuthorized": False,
              "releaseAuthorized": False, "publisherAuthorized": False}
    print(json.dumps(result, sort_keys=True))
    print("STATIC_AND_NOTICE_INVENTORY=OBSERVED RIGHTS=UNVERIFIED "
          "RUNTIME=UNVERIFIED PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection-file", type=Path, required=True)
    parser.add_argument("--pg-major", choices=tuple(PINS), required=True)
    args = parser.parse_args()
    run(json.loads(args.selection_file.read_text(encoding="utf-8")), args.pg_major)
