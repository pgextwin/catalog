#!/usr/bin/env python3
"""Nonpublishing, read-only OSGeo original licensing/dependency inventory.

No binary/ZIP is uploaded or redistributed. An inventory is not independent
signed issuance, rights closure, or dynamic dependency/provenance clearance.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import zipfile

from issue112_osgeo_original_byte_pilot import inspect, read_original

NAME = "postgis-bundle-pg18-3.7.0x64.zip"
ORIGIN = "https://download-cache.osgeo.org/postgis/windows/pg18/" + NAME
SIZE = 83_320_975
SHA256 = "fa3db8060d8d376e869d961659bf4eff326c0d99a731396701af61a13dc12a40"
ROOT = NAME[:-4] + "/"
LICENSES = (ROOT + "LICENSE", ROOT + "bin/COPYING", ROOT + "gdal-data/LICENSE.TXT")
MAX_LICENSE_BYTES = 512 * 1024


def audit_archive(path: Path):
    # Reuse bounded ZIP/member/path/symlink/CRC/PE guards from the exact
    # original-byte pilot. They do not establish a license or signature.
    integrity = inspect(path)
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        if any(name not in names for name in LICENSES):
            raise ValueError("Missing exact in-bundle license/COPYING file")
        receipts = []
        for name in LICENSES:
            info = archive.getinfo(name)
            if info.is_dir() or not 0 < info.file_size <= MAX_LICENSE_BYTES:
                raise ValueError("Empty or oversized original license: " + name)
            with archive.open(info) as stream:
                content = stream.read(MAX_LICENSE_BYTES + 1)
            if len(content) != info.file_size:
                raise ValueError("Incomplete original license: " + name)
            preview = " ".join(content.decode("utf-8", errors="replace")[:300].split())[:180]
            receipts.append({"path": name, "bytes": len(content),
                             "sha256": hashlib.sha256(content).hexdigest(),
                             "openingText": preview})
        compiled = sorted(name for name in names if name.lower().endswith(".dll"))
        if not any(name.lower().endswith("/postgis-3.dll") for name in compiled):
            raise ValueError("PostGIS native DLL absent")
        if not any(name.lower().endswith("/libpgrouting-4.0.dll") for name in compiled):
            raise ValueError("pgRouting native DLL absent")
    return {
        "schemaVersion": "pgextwin-osgeo-rights-inventory-nonpublishing/v1",
        "source": ORIGIN, "expectedOriginalBytes": SIZE,
        "expectedOriginalSha256": SHA256, "zipMembers": integrity["zipMembers"],
        "dllCount": len(compiled), "licenseFiles": receipts,
        "technicalWindowsSqlRun": "https://github.com/pgextwin/catalog/actions/runs/42871493748",
        "independentSignedAdmission": False,
        "licenseClosureVerified": False, "dynamicDependenciesVerified": False,
        "sourceToBinaryProvenanceVerified": False,
        "downloadAuthorized": False, "redistributionAuthorized": False,
        "mirrorAuthorized": False, "publisherAuthorized": False,
    }


def main():
    with tempfile.TemporaryDirectory(prefix="pgextwin-osgeo-rights-") as directory:
        target = Path(directory) / NAME
        size, digest = read_original(ORIGIN, target)
        if size != SIZE or digest != SHA256:
            raise ValueError("OSGeo original bytes changed; fail closed")
        result = audit_archive(target)
    print(json.dumps(result, sort_keys=True, ensure_ascii=True))
    print("OSGEO_LICENSE_INVENTORY=OBSERVED RIGHTS_CLOSURE=NOT_YET_VERIFIED "
          "DYNAMIC_DEPS=NOT_YET_VERIFIED SOURCE_PROVENANCE=NOT_YET_VERIFIED "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY")


if __name__ == "__main__":
    main()
