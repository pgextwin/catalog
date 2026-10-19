"""Hostile local candidate evidence tests. No GitHub API or network."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SOURCE = "a" * 40
RUN = "123456"
SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "cli_r6_candidate.py"
spec = importlib.util.spec_from_file_location("cli_r6_candidate", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.exe = root / "pgextwin.exe"
        self.exe.write_bytes(b"P" * 1_000_000)
        self.receipt = root / "candidate-evidence.json"
        self.size, self.digest = mod.inspect_binary(self.exe)
        self.data = dict(schema="pgextwin-cli-r6-candidate/v1",
                         name="pgextwin.exe", version="0.2.0-preview.1",
                         sourceCommit=SOURCE, sdkObserved="10.0.402", runId=RUN,
                         sha256=self.digest, bytes=self.size,
                         signatureVerified=False, provenanceVerified=False,
                         publishAuthorized=False, distributionAuthorized=False)

    def test_unverified_receipt_passes(self):
        mod.check(self.data, self.size, self.digest, SOURCE, RUN)

    def test_mutated_original_bytes_denied(self):
        self.exe.write_bytes(b"X" + b"P" * 999_999)
        _, actual = mod.inspect_binary(self.exe)
        with self.assertRaises(ValueError):
            mod.check(self.data, self.size, actual, SOURCE, RUN)

    def test_mismatched_source_and_run_denied(self):
        for source, run in [("b" * 40, RUN), (SOURCE, "456")]:
            with self.subTest(source=source, run=run):
                with self.assertRaises(ValueError):
                    mod.check(self.data, self.size, self.digest, source, run)

    def test_all_four_escalation_flags_denied(self):
        for key in ("signatureVerified", "provenanceVerified",
                    "publishAuthorized", "distributionAuthorized"):
            with self.subTest(flag=key):
                poisoned = dict(self.data, **{key: True})
                with self.assertRaises(ValueError):
                    mod.check(poisoned, self.size, self.digest, SOURCE, RUN)

    def test_duplicate_json_key_denied(self):
        raw = json.dumps(self.data).replace('"name": "pgextwin.exe",',
                                            '"name": "pgextwin.exe", "name": "other",')
        with self.assertRaises(ValueError):
            mod.parse_receipt(raw)

    def test_missing_extra_keys_denied(self):
        for bad in [dict(self.data, irrelevant=1),
                    {k: v for k, v in self.data.items() if k != "sha256"}]:
            with self.assertRaises(ValueError):
                mod.parse_receipt(json.dumps(bad))

    def test_wrong_binary_path_denied(self):
        self.exe.rename(self.exe.with_name("other.exe"))
        with self.assertRaises(ValueError):
            mod.inspect_binary(self.exe.with_name("other.exe"))


if __name__ == "__main__":
    unittest.main()
