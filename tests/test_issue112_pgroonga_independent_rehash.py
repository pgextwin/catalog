"""Offline hostile tests for independent public-byte receipts; no network needed."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgroonga_independent_rehash as probe


class IndependentRehashTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)

    def test_source_tar_pin_is_explicit_and_not_mutable_latest(self):
        name, url, size, digest = probe.original_pin("source")
        self.assertEqual(name, "groonga-16.1.3.tar.gz")
        self.assertEqual(size, 110532722)
        self.assertEqual(digest, "61e1c8f1671e22d7bf4cd8c35002b9674d29ba82ae2cbe6835d73d3a45af202b")
        self.assertTrue(url.startswith("https://github.com/groonga/groonga/releases/download/v16.1.3/"))
        self.assertNotIn("latest", url)

    def test_postgresql_pins_are_existing_strict_originals(self):
        for pg in range(14, 19):
            name, url, size, sha = probe.original_pin(str(pg))
            self.assertIn(f"postgresql-{pg}-x64.zip", name)
            self.assertEqual((size, sha), probe.rights.PINS[pg])
            self.assertIn("/releases/download/4.1.0/", url)

    def test_fresh_bytes_hash_and_size_are_independently_checked(self):
        data = b"independent real bytes"
        path = self.base / "ok"
        expected = hashlib.sha256(data).hexdigest()
        self.assertEqual(probe.copy_checked_bytes(io.BytesIO(data), path,
                          len(data), expected), (len(data), expected))
        self.assertEqual(path.read_bytes(), data)

    def test_tampered_bytes_rejected(self):
        data = b"original"
        with self.assertRaisesRegex(ValueError, "mismatch"):
            probe.copy_checked_bytes(io.BytesIO(b"tampered"),
                                     self.base / "tamper", len(data),
                                     hashlib.sha256(data).hexdigest())

    def test_truncation_rejected(self):
        data = b"original"
        with self.assertRaisesRegex(ValueError, "mismatch"):
            probe.copy_checked_bytes(io.BytesIO(data[:-1]),
                                     self.base / "short", len(data),
                                     hashlib.sha256(data).hexdigest())

    def test_oversize_rejected_before_writing_unbounded_bytes(self):
        data = b"data too long"
        with self.assertRaisesRegex(ValueError, "exceed"):
            probe.copy_checked_bytes(io.BytesIO(data), self.base / "long",
                                     2, hashlib.sha256(data).hexdigest())

    def test_unpinned_postgresql_major_rejected(self):
        with self.assertRaises(ValueError):
            probe.original_pin("19")

    def test_target_list_has_no_authorization_mode(self):
        self.assertEqual(probe.TARGETS, ("source", "14", "15", "16", "17", "18"))
        self.assertTrue(all("publish" not in x and "authorize" not in x
                            for x in probe.TARGETS))


if __name__ == "__main__":
    unittest.main()
