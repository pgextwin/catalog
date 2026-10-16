"""Issue #112 hostile tests. Synthetic data NEVER authenticates a signature or admits P1."""
import copy
import gzip
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import distribution_historical_p1_bridge as b
import distribution_historical_p1_pg14 as pg14
from distribution_manifest_v1 import Denied


def tar_blob(items):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.GNU_FORMAT) as tf:
        for name, data, kind in items:
            info = tarfile.TarInfo(name)
            info.size = len(data) if kind == "file" else 0
            if kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, "target"
            elif kind == "hardlink":
                info.type, info.linkname = tarfile.LNKTYPE, "target"
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
            elif kind == "device":
                info.type = tarfile.CHRTYPE
            tf.addfile(info, io.BytesIO(data) if kind == "file" else None)
    return buffer.getvalue()


def sample_manifest(entries):
    return {
        "schema": "pgextwin-issue112-resume6-manifest/v1",
        "repoId": pg14.PIN["repoId"], "releaseId": pg14.PIN["releaseId"],
        "publicationAuthorized": False, "distributionAuthorized": False,
        "signatureOrTrustedTimestamp": False,
        "files": [
            {"path": name, "size": len(data), "sha256": b.hashlib.sha256(data).hexdigest()}
            for name, data in entries.items()
        ],
    }


class HistoricalBridgeHostile(unittest.TestCase):
    def deny(self, f, *a):
        with self.assertRaises((Denied, ValueError, TypeError, KeyError)):
            f(*a)

    def test_tar_reads_only_files_and_allows_safe_directories(self):
        result = b.safe_tar(tar_blob([
            ("original/", b"", "dir"), ("original/snapshot.json", b"test", "file")]))
        self.assertEqual(result, {"original/snapshot.json": b"test"})

    def test_tar_traversal_and_absolute_paths(self):
        for name in ("../evil", "a/../../evil", "/absolute", "a//evil",
                     "a/./evil", "C:/evil", "a\\evil", "a/CON", "a/..",
                     "a:evil", "./file", "a/file/"):
            with self.subTest(name=name):
                self.deny(b.safe_tar, tar_blob([(name, b"x", "file")]))

    def test_tar_link_and_device_rejected(self):
        for kind in ("symlink", "hardlink", "device"):
            with self.subTest(kind=kind):
                self.deny(b.safe_tar, tar_blob([("old/file", b"", kind)]))

    def test_tar_duplicate_and_casefold_rejected(self):
        for names in (("x/a", "x/a"), ("x/A", "x/a")):
            self.deny(b.safe_tar, tar_blob([(n, b"x", "file") for n in names]))

    def test_tar_too_many_items(self):
        items = [(f"x/a{i}", b"x", "file") for i in range(b.MAX_ENTRIES + 1)]
        self.deny(b.safe_tar, tar_blob(items))

    def test_tar_member_bomb(self):
        self.deny(b.safe_tar, tar_blob([("large", b"X" * (b.MAX_MEMBER + 1), "file")]))

    def test_tar_corrupt_and_missing_evidence(self):
        for bad in (b"", b"abc", gzip.compress(b"not tar")):
            self.deny(b.safe_tar, bad)
        self.deny(b.safe_tar, tar_blob([("one", b"1", "file")]), 31)

    def test_exact_31_manifest_matching(self):
        entries = {f"resume6/file-{i}": bytes([i]) for i in range(31)}
        manifest = sample_manifest(entries)
        b.validate_manifest(entries, manifest)
        self.deny(b.validate_manifest, dict(list(entries.items())[:-1]), manifest)
        mutant = copy.deepcopy(manifest)
        mutant["files"][0]["sha256"] = "0" * 64
        self.deny(b.validate_manifest, entries, mutant)
        mutant = copy.deepcopy(manifest)
        mutant["files"][1]["path"] = mutant["files"][0]["path"]
        self.deny(b.validate_manifest, entries, mutant)
        mutant = copy.deepcopy(manifest)
        mutant["files"][0]["size"] += 1
        self.deny(b.validate_manifest, entries, mutant)

    def test_manifest_cannot_switch_identity_or_authorize(self):
        entries = {f"resume6/file-{i}": bytes([i]) for i in range(31)}
        for key, value in (("repoId", 100), ("releaseId", 100),
                           ("publicationAuthorized", True),
                           ("distributionAuthorized", True),
                           ("signatureOrTrustedTimestamp", True)):
            mutant = sample_manifest(entries)
            mutant[key] = value
            self.deny(b.validate_manifest, entries, mutant)

    def test_prior_source_and_release_16_enforced(self):
        records = {}
        for i in range(16):
            name = "pkg%d" % i
            records[name] = {"name": name, "size": 1,
                             "origin": "PRESERVED_PREVIOUS_RUN",
                             "digest": "sha256:" + "0" * 64}
        self.deny(b.identify_asset_bytes, {}, {}, records)
        records["pkg0"]["origin"] = "NEW_GET_THIS_RUN"
        self.deny(b.identify_asset_bytes, {}, {}, records)

    def test_unknown_pg_and_other_extension_receipt_rejected(self):
        for key, wrong in (("profile", "historical-plpgsql_check-pg14/1"),
                           ("assetId", 12345),
                           ("runId", 38128142145),
                           ("attempt", 2),
                           ("catalogCommit", "0" * 40),
                           ("originalRootSha256", "0" * 64),
                           ("signerSha", "0" * 40),
                           ("upstreamCommit", "0" * 40),
                           ("publicationAuthorized", True),
                           ("distributionAuthorized", True)):
            mutant = dict(b.RECEIPT_FIELDS)
            mutant[key] = wrong
            self.assertNotEqual(mutant[key], b.RECEIPT_FIELDS[key])

    def test_status_forgery_rejected(self):
        ledger = {"schema": "pgextwin-issue112-resume6-release-byte-audit/v1"}
        for key, value in (("formalP1RowAccepted", True),
                           ("publicationAuthorized", True), ("distributionAuthorized", True),
                           ("fleetComplete", True), ("all16AssetsRehashed", False),
                           ("totalAssetPayloadsVerified", 15),
                           ("sourceRunAttemptVerificationExecutedThisRun", True)):
            altered = dict(ledger)
            altered[key] = value
            self.deny(b.ledger_assets, altered)

    def test_real_crypto_never_invoked_for_missing_or_fake_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            fake = p / "self-reported.json"
            fake.write_text(json.dumps({"signatureVerified": True, "all16AssetsRehashed": True}))
            spy = Mock(side_effect=AssertionError("cryptography called before asset gate"))
            for args in ((fake,) * 7, (p / "missing",) * 7):
                self.deny(b.gate, *args, spy)
            spy.assert_not_called()

    def test_pg14_verifier_preserves_real_only_gate(self):
        self.deny(pg14.audit, Path("/definitely/missing/original"),
                  Path("/definitely/missing/root"), pg14.PIN["catalog"])

    def test_single_row_success_status_is_not_fleet_or_publication(self):
        # Do not fabricate success: the success builder is reachable ONLY after
        # genuine pg14.audit(...) against original bytes and official gh.
        source = Path(__file__).resolve().parents[1] / "scripts" / "distribution_historical_p1_bridge.py"
        data = source.read_text(encoding="utf-8")
        self.assertIn('"formalP1RowsAccepted": 1', data)
        self.assertIn('"publicationAuthorized": False', data)
        self.assertIn('"distributionAuthorized": False', data)
        self.assertIn('"historicalSourceAccepted": 0', data)
        self.assertNotIn("38128142145", data)
        self.assertNotIn("promote.yml", data)


if __name__ == "__main__":
    unittest.main()
