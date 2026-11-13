#!/usr/bin/env python3
"""Private PGroonga source-owned Windows build input gate, never GET admission.

This builds a DIFFERENT output from historical official PGroonga 4.1.0 ZIPs.
The official mutable groonga-latest.zip input remains historically unverified.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import zipfile

PGROONGA_REPO = "pgroonga/pgroonga"
PGROONGA_COMMIT = "47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc"
GROONGA_REPO = "groonga/groonga"
GROONGA_COMMIT = "9085dd417e5cd42cd8f1a367aaf24cfe45dd9f1f"
GROONGA_TAG = "v16.1.3"
SOURCE = ("groonga-16.1.3.zip", 136286598,
          "ad892560511e5886dea2373101f0780e0a16394d30e5a20a8d3df12d7ef9e85d")
SIGNATURE = ("groonga-16.1.3.zip.asc", 833,
             "edc58ee987bf8ef92436a7c11373ddb382af4063d59aac8bd2c4943f65223848")
SIGNER = "2701F317CFCCCB975CADE9C2624CF77434839225"
DENY = {
    "originalPGroongaReleaseAssetProvenanceEstablished": False,
    "allSourceDependenciesAndToolchainPinned": False,
    "allLicenseNoticeObligationsAccepted": False,
    "independentSourceOwnedBinaryAttestationVerified": False,
    "sourceSpecificOwnerAdmissionVerified": False,
    "publicGetAuthorized": False,
    "mirrorAuthorized": False,
    "redistributionAuthorized": False,
    "releaseAuthorized": False,
    "publisherAuthorized": False,
}

def require(condition, reason):
    if not condition:
        raise ValueError("PGroonga owned-source DENY: " + reason)

def hash_file(path, expected, maximum):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "missing or linked input")
    require(0 < path.stat().st_size <= maximum, "unbounded input")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    require((path.name, path.stat().st_size, digest.hexdigest()) == expected,
            "source ZIP/ASC exact filename, length or SHA256 mismatch")
    return digest.hexdigest()

def source_commit(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), "missing PGroonga source")
    process = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=10, check=False)
    require(process.returncode == 0 and process.stdout.strip() == PGROONGA_COMMIT,
            "PGroonga source commit not fixed")
    return PGROONGA_COMMIT

def archive_members(path):
    """Validate bounded, nontraversing source ZIP before Windows extraction."""
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        require(0 < len(infos) <= 100000, "source ZIP member count")
        seen = set()
        total = 0
        paths = set()
        for entry in infos:
            name = entry.filename
            require(type(name) is str and 0 < len(name) <= 350 and
                    not name.startswith("/") and "\\" not in name and
                    ":" not in name and not re.search(r"[\x00-\x1f]", name),
                    "unsafe source ZIP path")
            parts = PurePosixPath(name).parts
            require(parts and parts[0] == "groonga-16.1.3" and
                    not any(p in ("", ".", "..") for p in name.strip("/").split("/")),
                    "wrong ZIP source root or traversal")
            require(name not in seen and name.lower() not in paths,
                    "duplicate or case-insensitive source path")
            seen.add(name)
            paths.add(name.lower())
            mode = (entry.external_attr >> 16) & 0o170000
            require(mode != stat.S_IFLNK, "source ZIP symlink")
            require(entry.file_size <= 1024 * 1024 * 1024, "huge source member")
            total += entry.file_size
            require(total <= 4 * 1024**3, "source ZIP expansion cap")
        require("groonga-16.1.3/CMakeLists.txt" in seen,
                "Groonga CMake source entry missing")
    return {"members": len(seen), "declaredExpandedBytes": total}

def inspect(source_zip, asc, pgroonga_root=None, *, source_pin=SOURCE, asc_pin=SIGNATURE):
    # Substituted pins are ONLY for offline adversarial tests; the CLI never
    # accepts caller-supplied sizes, URLs or digests.
    hash_file(source_zip, source_pin, 200 * 1024**2)
    hash_file(asc, asc_pin, 10000)
    observed = archive_members(source_zip)
    if pgroonga_root is not None:
        source_commit(pgroonga_root)
    return {
        "schemaVersion": "pgextwin-issue112-pgroonga-owned-source-private-pg18/v1",
        "scope": "SOURCE_OWNED_NEW_BUILD_NOT_OFFICIAL_ORIGINAL",
        "pgMajor": 18,
        "pgroongaSourceRepo": PGROONGA_REPO,
        "pgroongaCommit": PGROONGA_COMMIT,
        "groongaSourceRepo": GROONGA_REPO,
        "groongaGitTag": GROONGA_TAG,
        "candidateGroongaTagCommitForRightsReview": GROONGA_COMMIT,
        "sourceZipToGitTreeByteEquivalenceVerified": False,
        "historicalGroongaLatestZipInputSha256Known": False,
        "groongaSourceZipSha256": SOURCE[2],
        "groongaSourceZipBytes": SOURCE[1],
        "groongaDetachedSignatureSha256": SIGNATURE[2],
        "expectedOfficialGroongaKeyFingerprint": SIGNER,
        "detachedSignatureCryptographicallyVerifiedByCaller": False,
        "archive": observed,
        **DENY,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", required=True, type=Path)
    parser.add_argument("--asc", required=True, type=Path)
    parser.add_argument("--pgroonga-root", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.zip, args.asc, args.pgroonga_root),
                     sort_keys=True))
    print("SOURCE_BYTES=PINNED GPG_AUTHENTICITY=SEPARATE_CHECK "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")

if __name__ == "__main__":
    main()
