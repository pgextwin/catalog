"""Offline hostile tests for nonpublishing Cybertec/native overlap classification."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_cybertec_native_gap as gap


def candidate(name, major):
    return {"extension": name, "pgMajor": major, "fileName": f"{name}-{major}-public-v1.zip",
            **{field: False for field in gap.DENIALS}}


def make_report():
    rows = [candidate(n, pg) for n in ("pgtap", "pg_crash") for pg in sorted(gap.MAJORS)]
    return {"schemaVersion": "pgextwin-issue112-cybertec-windows-index/v1",
            "trust": "UNTRUSTED_DIRECTORY_METADATA_ONLY",
            "providerPackaging": "CYBERTEC_PGEE_COMMUNITY_PG_COMPATIBILITY_UNVERIFIED",
            "latestVersionResolution": "NOT_VERIFIED", "pgMajorsObserved": sorted(gap.MAJORS),
            "zipCandidates": len(rows), "extensionNamesObserved": 2,
            "completeObservedFiveMajorNames": ["pg_crash", "pgtap"],
            "candidates": rows,
            **{flag: False for flag in ("sourceArchiveDownloaded", "binaryArchiveDownloaded",
                                            "publicGetAuthorized", "mirrorAuthorized",
                                            "publisherAuthorized", "releaseAuthorized")}}


class GapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "extensions").mkdir()
        self.native = self.root / "extensions" / "pgtap.json"
        self.native.write_text(json.dumps({"schemaVersion": 2, "name": "pgtap",
            "latest": {"releaseTag": "v1.3.4-windows.1"},
            "postgresql": {pg: {"available": True, "asset": "pgtap.zip", "sha256": "a" * 64}
                           for pg in gap.MAJORS}}), "utf-8")

    def test_detects_native_overlap_and_gaps_with_all_denials(self):
        result = gap.classify(make_report(), self.root)
        self.assertEqual(result["catalogNativeOverlappingNames"], ["pgtap"])
        self.assertEqual(result["notInNativeCatalogFiveMajorObservedNames"], ["pg_crash"])
        self.assertEqual(result["catalogNativeOverlappingMajorDeclarations"]["pgtap"], sorted(gap.MAJORS))
        for field in ("publicGetAuthorized", "mirrorAuthorized", "publisherAuthorized", "releaseAuthorized"):
            self.assertIs(result[field], False)

    def test_partial_native_declaration_does_not_claim_full_coverage(self):
        doc = json.loads(self.native.read_text("utf-8"))
        doc["postgresql"]["18"]["available"] = False
        self.native.write_text(json.dumps(doc), "utf-8")
        result = gap.classify(make_report(), self.root)
        self.assertEqual(result["catalogNativeOverlappingMajorDeclarations"]["pgtap"], ["14", "15", "16", "17"])

    def test_blocks_escalated_flags_and_coverage_contradictions(self):
        for change in (lambda r: r.update(publicGetAuthorized=True),
                       lambda r: r["candidates"][0].update(independentSignedAdmission=True),
                       lambda r: r.update(completeObservedFiveMajorNames=[]),
                       lambda r: r["candidates"].append(copy.deepcopy(r["candidates"][0]))):
            with self.subTest(change=change), self.assertRaises(ValueError):
                doc = make_report()
                change(doc)
                gap.classify(doc, self.root)

    def test_rejects_path_injection_malformed_native_and_symlink(self):
        doc = make_report()
        doc["candidates"][0]["extension"] = "../pgtap"
        with self.assertRaises(ValueError):
            gap.classify(doc, self.root)
        self.native.write_text('{"schemaVersion":2,"name":"wrong"}', "utf-8")
        with self.assertRaisesRegex(ValueError, "Contradictory"):
            gap.classify(make_report(), self.root)
        self.native.unlink()
        self.native.symlink_to(self.root / "not-a-real-file")
        with self.assertRaises(ValueError):
            gap.classify(make_report(), self.root)

    def test_accepts_only_exact_script_envelope_and_rejects_duplicate_json_keys(self):
        p = self.root / "report.json"
        p.write_text(json.dumps(make_report()) + "\n" + gap.TRAILER + "\n", "utf-8")
        self.assertEqual(len(gap.load_index(p)["candidates"]), 10)
        p.write_text('{"schemaVersion":"x","schemaVersion":"y"}', "utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            gap.load_index(p)
        p.write_text(json.dumps(make_report()) + "\nUNEXPECTED OUTPUT\n", "utf-8")
        with self.assertRaisesRegex(ValueError, "envelope"):
            gap.load_index(p)

    def test_rejects_oversize_and_does_no_network(self):
        p = self.root / "report.json"
        p.write_bytes(b"x" * (gap.MAX_REPORT_BYTES + 1))
        with self.assertRaises(ValueError):
            gap.load_index(p)
        self.assertFalse(hasattr(gap, "urllib"))


if __name__ == "__main__":
    unittest.main()
