#!/usr/bin/env python3
"""Re-prove the sealed P1 Git tree; requires explicit full-history checkout."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import distribution_p1_batch as batch
from distribution_manifest_v1 import Denied

# Sealed 2026-10-17 evidence: never repin this historic snapshot to a newer
# Catalog worktree merely because a genuine public Release was published.
HISTORICAL_CATALOG_COMMIT = "e372e2c6a95adcf8227ea82d6253df3792b6f029"
HISTORICAL_PLPGSQL_SHA256 = "5e041e65b139d710cc2863036027d36955ad5c9026a2e1a67836a18a90890d13"
HISTORICAL_POLICY = "config/issue112-p1-fleet-pins-20261017.json"
ROOT = Path(__file__).resolve().parents[2]


def read_sealed_catalog_blob(commit, path):
    """Read bytes from the *exact* historical Git tree, never the worktree.

    Validate both arguments before passing a single immutable SHA:path git
    object argument; missing/unavailable Git history fails closed.
    """
    if commit != HISTORICAL_CATALOG_COMMIT:
        raise Denied("historical Catalog commit identity moved")
    allowed = {"index.json"} | {"extensions/" + name + ".json" for name in batch.NAMES}
    if path not in allowed:
        raise Denied("path not in historical Catalog inventory")
    result = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{commit}:{path}"],
        capture_output=True, check=True,
    )
    return result.stdout


def verify_sealed_catalog_snapshot(policy, read_blob=read_sealed_catalog_blob):
    """Fail on a changed policy, missing Git object or mutated historical blob."""
    if policy.get("catalogCommitSha") != HISTORICAL_CATALOG_COMMIT:
        raise Denied("historical Catalog commit pin changed")
    digests = policy.get("catalogDigests")
    allowed = {"index.json"} | {"extensions/" + name + ".json" for name in batch.NAMES}
    if not isinstance(digests, dict) or set(digests) != allowed:
        raise Denied("historical Catalog manifest inventory changed")
    if digests["extensions/plpgsql_check.json"] != HISTORICAL_PLPGSQL_SHA256:
        raise Denied("historical plpgsql_check digest was repinned")
    for path, expected_hash in sorted(digests.items()):
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise Denied("historical Catalog digest malformed: " + path)
        data = read_blob(HISTORICAL_CATALOG_COMMIT, path)
        if not isinstance(data, bytes) or hashlib.sha256(data).hexdigest() != expected_hash:
            raise Denied("historical Catalog Git object mismatches pinned SHA256: " + path)


class SealedCatalogSnapshotTests(unittest.TestCase):
    def test_immutable_catalog_pins_match_exact_repository_files(self):
        policy = json.loads((ROOT / HISTORICAL_POLICY).read_text(encoding="utf-8"))
        self.assertEqual(policy["catalogCommitSha"], HISTORICAL_CATALOG_COMMIT)
        self.assertEqual(set(policy["repoIds"]), set(batch.NAMES))
        self.assertEqual(set(policy["releaseIds"]), set(batch.NAMES))
        self.assertEqual(set(policy["assetIds"]), set(batch.NAMES))
        self.assertEqual(sum(map(len, policy["assetIds"].values())), 224)
        # Historical hashes are matched to actual bytes in the sealed Git
        # commit, not to mutable current Catalog files or an unsigned fixture.
        verify_sealed_catalog_snapshot(policy)

    def test_historical_catalog_snapshot_rejects_tampering_and_repinning(self):
        policy = json.loads((ROOT / HISTORICAL_POLICY).read_text(encoding="utf-8"))
        historical_path = "extensions/plpgsql_check.json"
        authentic = read_sealed_catalog_blob(HISTORICAL_CATALOG_COMMIT, historical_path)
        self.assertEqual(hashlib.sha256(authentic).hexdigest(),
                         HISTORICAL_PLPGSQL_SHA256)
        with self.assertRaises(Denied):
            read_sealed_catalog_blob("a" * 40, historical_path)
        for path in ("../secrets", "extensions/../index.json", "extensions/unknown.json"):
            with self.subTest(path=path), self.assertRaises(Denied):
                read_sealed_catalog_blob(HISTORICAL_CATALOG_COMMIT, path)
        for mutation in ("commit", "digest", "inventory"):
            changed = json.loads(json.dumps(policy))
            if mutation == "commit":
                changed["catalogCommitSha"] = "0" * 40
            elif mutation == "digest":
                changed["catalogDigests"][historical_path] = "0" * 64
            else:
                del changed["catalogDigests"][historical_path]
            with self.subTest(mutation=mutation), self.assertRaises(Denied):
                verify_sealed_catalog_snapshot(changed)
        def substituted_blob(commit, path):
            if path == historical_path:
                return authentic + b"\n"  # changed historic bytes, original pinned SHA
            return read_sealed_catalog_blob(commit, path)
        with self.assertRaises(Denied):
            verify_sealed_catalog_snapshot(policy, read_blob=substituted_blob)

    def test_new_live_release_record_does_not_mutate_historical_acceptance(self):
        policy = json.loads((ROOT / HISTORICAL_POLICY).read_text(encoding="utf-8"))
        # A new public Release can update today's worktree, while the sealed
        # historic bytes and count of accepted rows remain independently fixed.
        # Deliberately deny any worktree read by the historic check.
        with patch.object(Path, "read_bytes", side_effect=AssertionError(
                "historical check must not read the mutable current worktree")):
            verify_sealed_catalog_snapshot(policy)
        self.assertEqual(len(batch.NAMES) * len(batch.MAJORS), 70)
        self.assertEqual(policy["catalogDigests"]["extensions/plpgsql_check.json"],
                         HISTORICAL_PLPGSQL_SHA256)


if __name__ == "__main__":
    unittest.main()
