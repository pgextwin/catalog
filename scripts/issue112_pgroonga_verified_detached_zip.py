#!/usr/bin/env python3
"""Verify PGroonga 4.1.0 official ZIP bytes against independently pinned Groonga OpenPGP key.

DENY-only independent audit; passing signatures are not source-to-binary attestations,
owner-signed admission, redistribution permissions, or Publisher authority.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request
from urllib.parse import urlsplit

import issue112_pgroonga_detached_signature_review as prior
from issue112_pgroonga_independent_rehash import copy_checked_bytes

FINGERPRINT = "2701F317CFCCCB975CADE9C2624CF77434839225"
# Independently published in official groonga/groonga source, at an immutable Git commit.
FINGERPRINT_SOURCE = (
    "https://raw.githubusercontent.com/groonga/groonga/"
    "b4c1e7f13254e619dbdf0eeb164186b244ce07ae/gpg_uid_rsa4096"
)
# Groonga's own HTTPS package server. Key material is not selected by .asc packet hints.
KEYRING_SOURCE = "https://packages.groonga.org/debian/groonga-archive-keyring.asc"
ALLOWED_RELEASE_HOSTS = {
    "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"
}
DENY = {
    "signedSourceToBinaryBuildProvenanceVerified": False,
    "allComponentRightsNoticesVerified": False,
    "independentOwnerSignedAdmission": False,
    "publicGetAuthorized": False,
    "mirrorAuthorized": False,
    "releaseAuthorized": False,
    "publisherAuthorized": False,
}


def download(url, path, size, sha256=None, hosts=None, exact_url=False):
    """Bound bytes before treating any fetched file as evidence."""
    if not url.startswith("https://") or size <= 0 or size > 100_000_000:
        raise ValueError("Unsafe download constraints")
    if path.exists() or path.is_symlink():
        raise ValueError("Download destination already exists")
    request = urllib.request.Request(url, headers={
        "User-Agent": "pgextwin-issue112-pgroonga-trusted-signature-review/1"})
    with urllib.request.urlopen(request, timeout=120) as stream:
        final = stream.geturl()
        parsed = urlsplit(final)
        if (parsed.scheme != "https" or parsed.hostname not in hosts or
                (exact_url and final != url)):
            raise ValueError("Unexpected HTTPS download redirect")
        if sha256:
            return copy_checked_bytes(stream, path, size, sha256)
        digest = hashlib.sha256()
        count = 0
        with path.open("xb") as output:
            while chunk := stream.read(min(1024 * 1024, size + 1)):
                count += len(chunk)
                if count > size:
                    raise ValueError("Key material exceeds bound")
                output.write(chunk)
                digest.update(chunk)
    if not count:
        raise ValueError("Empty key material")
    return count, digest.hexdigest()


def run(*args, timeout=35):
    p = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
    if p.returncode:
        raise ValueError("GnuPG command failed: " + " ".join(args[:3]) +
                         " code=" + str(p.returncode))
    return p.stdout


def verified_keyring(keyfile, homedir):
    """Export only the independently selected full fingerprint into an isolated ring."""
    homedir.mkdir(mode=0o700)
    run("gpg", "--homedir", str(homedir), "--batch", "--no-auto-key-retrieve",
        "--import", str(keyfile))
    listed = run("gpg", "--homedir", str(homedir), "--batch", "--with-colons",
                 "--fingerprint", "--list-keys")
    observed = [line.split(b":")[9].decode("ascii").upper()
                for line in listed.splitlines() if line.startswith(b"fpr:")]
    if FINGERPRINT not in observed:
        raise ValueError("Official Groonga key fingerprint not present")
    exported = run("gpg", "--homedir", str(homedir), "--batch",
                   "--export", FINGERPRINT)
    if not exported:
        raise ValueError("Pinned public key export failed")
    ring = homedir.parent / "verified-groonga-pubkey.gpg"
    ring.write_bytes(exported)
    return ring


def verify_signature(signature, original, keyring, fingerprint=FINGERPRINT):
    """Require gpgv cryptography PLUS the entire externally approved fingerprint."""
    if not re.fullmatch(r"[0-9A-F]{40}", fingerprint):
        raise ValueError("Malformed trusted fingerprint")
    p = subprocess.run(["gpgv", "--status-fd", "1", "--keyring", str(keyring),
                        str(signature), str(original)],
                       capture_output=True, timeout=45, check=False)
    lines = [line.decode("ascii", errors="replace").strip().split()
             for line in p.stdout.splitlines() if line.startswith(b"[GNUPG:] ")]
    valid = [line for line in lines if len(line) >= 3 and line[1] == "VALIDSIG"]
    good = [line for line in lines if len(line) >= 3 and line[1] == "GOODSIG"]
    bad = [line for line in lines if len(line) >= 2 and line[1] in
           {"BADSIG", "ERRSIG", "REVKEYSIG", "EXPKEYSIG"}]
    if (p.returncode or bad or len(valid) != 1 or len(good) != 1 or
            not (valid[0][2] == fingerprint or
                 (len(valid[0]) > 3 and valid[0][-1] == fingerprint))):
        raise ValueError("Invalid signature, untrusted fingerprint or wrong ZIP")
    return valid[0][2]


def audit(baseline, pg_majors, release=None):
    original = prior.strict_baseline(baseline)
    rows = prior.validate_metadata(release or prior.github_release(), original)
    lookup = {row["pgMajor"]: row for row in rows}
    if not pg_majors or len(set(pg_majors)) != len(pg_majors) or set(pg_majors) - set(lookup):
        raise ValueError("Missing, duplicate or unsupported PostgreSQL majors")
    with tempfile.TemporaryDirectory(prefix="issue112-pgroonga-gpgv-") as root:
        tmp = Path(root)
        fingerprint_source = tmp / "groonga-upstream-fingerprint"
        download(FINGERPRINT_SOURCE, fingerprint_source, 128,
                 hosts={"raw.githubusercontent.com"}, exact_url=True)
        if fingerprint_source.read_text(encoding="ascii").strip() != FINGERPRINT:
            raise ValueError("Independently published upstream fingerprint changed")
        key_source = tmp / "groonga-archive-keyring.asc"
        key_bytes, key_sha256 = download(KEYRING_SOURCE, key_source, 16384,
                                        hosts={"packages.groonga.org"}, exact_url=True)
        keyring = verified_keyring(key_source, tmp / "gnupg")
        checked = []
        for pg in pg_majors:
            entry = original[pg]
            name = f"pgroonga-{prior.VERSION}-postgresql-{pg}-x64.zip"
            zip_path = tmp / name
            sig_path = tmp / (name + ".asc")
            zip_bytes, zip_hash = download(prior.URL + name, zip_path,
                                           entry["originalBytes"], entry["originalSha256"],
                                           hosts=ALLOWED_RELEASE_HOSTS)
            sid, ssize, ssha = prior.SIDECARS[pg]
            signature_bytes, signature_hash = download(
                prior.URL + name + ".asc", sig_path, ssize, ssha,
                hosts=ALLOWED_RELEASE_HOSTS)
            signer = verify_signature(sig_path, zip_path, keyring)
            checked.append({"pgMajor": pg, "zipAssetId": entry["assetId"],
                            "zipOriginalBytes": zip_bytes, "zipOriginalSha256": zip_hash,
                            "signatureAssetId": sid, "signatureBytes": signature_bytes,
                            "signatureSha256": signature_hash,
                            "cryptographicallyVerified": True,
                            "verifiedSignerFingerprint": FINGERPRINT,
                            "validSignaturePacketSigner": signer})
    return {"schemaVersion": "pgextwin-issue112-pgroonga-verified-detached-zip-deny-only/v1",
            "sourceRepo": prior.REPO, "releaseId": prior.RELEASE_ID,
            "releaseTag": prior.VERSION,
            "trustedFingerprintFromIndependentUpstreamSource": FINGERPRINT,
            "upstreamFingerprintSource": FINGERPRINT_SOURCE,
            "trustedKeySource": KEYRING_SOURCE,
            "downloadedKeyBytes": key_bytes, "downloadedKeySha256": key_sha256,
            "signedOriginalZipEvidence": checked, **DENY}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path,
                        default=Path(__file__).resolve().parents[1] /
                        "external/pgroonga-release-watch-baseline-v1.json")
    parser.add_argument("--pg", choices=sorted(prior.SIDECARS), action="append")
    args = parser.parse_args()
    majors = args.pg or sorted(prior.SIDECARS)
    print(json.dumps(audit(args.baseline, majors), sort_keys=True))
    print("GPGV=VERIFIED_SIGNED_ORIGINAL_BYTES PRODUCER_BUILD_ATTESTATION=UNVERIFIED "
          "RIGHTS_CLOSURE=UNVERIFIED OWNER_ADMISSION=NO "
          "PUBLIC_GET=DENY MIRROR=DENY RELEASE=DENY PUBLISH=DENY")


if __name__ == "__main__":
    main()
