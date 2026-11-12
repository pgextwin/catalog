"""Offline tampering, wrong signer and exact-byte verification tests (no provider GET)."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgroonga_verified_detached_zip as review


class VerifiedDetachedZIP(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_wrong_fingerprint_rejected_before_crypto(self):
        for wrong in ("624CF77434839225", "X" * 40, ""):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                review.verify_signature(self.root / "sig", self.root / "zip",
                                        self.root / "ring", wrong)

    def test_download_unsafe_parameters_and_destination(self):
        out = self.root / "artifact"
        for url, length in (("http://packages.groonga.org/key", 10),
                            ("https://packages.groonga.org/key", 0),
                            ("https://packages.groonga.org/key", 100_000_001)):
            with self.assertRaises(ValueError):
                review.download(url, out, length, hosts={"packages.groonga.org"})
        out.write_bytes(b"existing")
        with self.assertRaises(ValueError):
            review.download(review.KEYRING_SOURCE, out, 16384,
                            hosts={"packages.groonga.org"})

    def test_pinned_full_fingerprint_and_safe_defaults(self):
        self.assertEqual(review.FINGERPRINT,
                         "2701F317CFCCCB975CADE9C2624CF77434839225")
        self.assertEqual(review.KEYRING_SOURCE,
                         "https://packages.groonga.org/debian/groonga-archive-keyring.asc")
        self.assertTrue(all(value is False for value in review.DENY.values()))
        self.assertNotIn("github-actions[bot]", review.FINGERPRINT)

    def test_valid_detached_signature_and_hostile_bytes(self):
        home = self.root / "gnupg"
        home.mkdir(mode=0o700)
        subprocess.run(["gpg", "--homedir", str(home), "--batch",
                        "--pinentry-mode", "loopback", "--passphrase", "",
                        "--quick-generate-key", "Test Signer <test@invalid.example>",
                        "rsa2048", "sign", "0"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=35)
        listing = subprocess.check_output(
            ["gpg", "--homedir", str(home), "--batch", "--with-colons",
             "--fingerprint", "--list-keys"], timeout=10)
        fpr = next(line.split(b":")[9].decode()
                   for line in listing.splitlines() if line.startswith(b"fpr:"))
        keyring = self.root / "ring.gpg"
        keyring.write_bytes(subprocess.check_output(
            ["gpg", "--homedir", str(home), "--batch", "--export", fpr], timeout=10))
        original = self.root / "original.zip"
        signature = self.root / "original.zip.asc"
        original.write_bytes(b"exact original byte fixture")
        subprocess.run(["gpg", "--homedir", str(home), "--batch",
                        "--pinentry-mode", "loopback", "--passphrase", "",
                        "--local-user", fpr, "--output", str(signature),
                        "--detach-sign", str(original)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=20)
        self.assertEqual(review.verify_signature(signature, original, keyring, fpr), fpr)
        with self.assertRaises(ValueError):
            review.verify_signature(signature, original, keyring, "A" * 40)
        original.write_bytes(b"tampered original byte fixture")
        with self.assertRaises(ValueError):
            review.verify_signature(signature, original, keyring, fpr)
        original.write_bytes(b"exact original byte fixture")
        signature.write_bytes(b"forged OpenPGP signature")
        with self.assertRaises(ValueError):
            review.verify_signature(signature, original, keyring, fpr)


if __name__ == "__main__":
    unittest.main()
