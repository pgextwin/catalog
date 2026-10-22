"""Hostile tests for immutable nonpublishing 14 x 5 inventory."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from distribution_manifest_v1 import Denied, canonical
from distribution_offline_major_inventory_v1 import build, CATALOG_COMMIT, read_pinned_index
from distribution_p1_formal_ledger_v5 import V5, V4, PINS, FLEET


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.args = [read_pinned_index(), V5.read_bytes(),
                    V4.read_bytes(), PINS.read_bytes(), FLEET.read_bytes()]

    def test_complete_matrix_denies_exact_five(self):
        result = build(*self.args, catalog_commit=CATALOG_COMMIT)
        self.assertEqual(len(result["rows"]), 70)
        self.assertEqual(len(result["majors"]), 5)
        self.assertEqual(result["acceptedRecordRows"], 65)
        self.assertEqual(result["historicalSourceAcceptedFromExistingLedger"], 40)
        self.assertEqual({(x["extension"], x["pgMajor"]) for x in result["rows"]
                          if x["formalP1"] == "DENY"},
                         {("plpgsql_check", str(n)) for n in range(14, 19)})
        self.assertFalse(result["publicationAuthorized"])
        self.assertFalse(result["archiveGenerationAuthorized"])
        self.assertTrue(all(not x["complete"] for x in result["majors"]))
        self.assertEqual(canonical(result), canonical(build(*self.args, catalog_commit=CATALOG_COMMIT)))

    def test_wrong_catalog_commit(self):
        with self.assertRaises(Denied):
            build(*self.args, catalog_commit="0" * 40)

    def test_larger_live_roster_cannot_inherit_historical_acceptance(self):
        args=list(self.args)
        index=json.loads(args[0])
        index["extensions"].append("pg_variables")
        index["extensions"].sort()
        args[0]=canonical(index)
        with self.assertRaises(Denied):
            build(*args,catalog_commit=CATALOG_COMMIT)

    def test_duplicate_catalog_extension(self):
        args = list(self.args)
        index = json.loads(args[0])
        index["extensions"][0] = index["extensions"][1]
        args[0] = canonical(index)
        with self.assertRaises(Denied):
            build(*args, catalog_commit=CATALOG_COMMIT)

    def test_missing_catalog_extension(self):
        args = list(self.args)
        index = json.loads(args[0])
        index["extensions"].pop()
        args[0] = canonical(index)
        with self.assertRaises(Denied):
            build(*args, catalog_commit=CATALOG_COMMIT)

    def test_ledger_counter_forgery(self):
        args = list(self.args)
        ledger = json.loads(args[1])
        ledger["formalAcceptedTotal"] = 70
        args[1] = canonical(ledger)
        with self.assertRaises((Denied, ValueError, AssertionError)):
            build(*args, catalog_commit=CATALOG_COMMIT)

    def test_ledger_plpgsql_forgery(self):
        args = list(self.args)
        ledger = json.loads(args[1])
        ledger["newAcceptedRows"][0]["extension"] = "plpgsql_check"
        args[1] = canonical(ledger)
        with self.assertRaises((Denied, ValueError)):
            build(*args, catalog_commit=CATALOG_COMMIT)

    def test_duplicate_json_key(self):
        args = list(self.args)
        args[0] = b'{"schemaVersion":2,"schemaVersion":2,"extensions":[]}'
        with self.assertRaises(Denied):
            build(*args, catalog_commit=CATALOG_COMMIT)


if __name__ == "__main__":
    unittest.main()
