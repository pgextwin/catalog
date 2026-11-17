"""Old acceptance records never grant current publication/distribution rights."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import distribution_p1_formal_ledger_v2 as v2
import distribution_p1_formal_ledger_v3 as v3
import distribution_p1_formal_ledger_v4 as v4
import distribution_p1_formal_ledger_v5 as v5
import distribution_p1_historical_source as source
import distribution_p1_historical_source_ledger_v2 as source_v2


class HistoricalEvidenceAuthorityTests(unittest.TestCase):
    def test_old_formal_acceptance_cannot_authorize_current_publication(self):
        # Exercise actual readers, including their full sealed predecessor chain.
        records = [
            v2.validate(v2.LEDGER.read_bytes()),
            v3.validate(v3.LEDGER.read_bytes(), v3.PREVIOUS.read_bytes()),
            v4.validate(v4.V4.read_bytes(), v4.V3.read_bytes(),
                        v4.PINS.read_bytes(), v4.FLEET.read_bytes()),
            v5.validate(v5.V5.read_bytes(), v5.V4.read_bytes(),
                        v5.PINS.read_bytes(), v5.FLEET.read_bytes()),
        ]
        for record in records:
            with self.subTest(decision=record["decision"]):
                self.assertIs(record["publicationAuthorized"], False)
                self.assertIs(record["distributionAuthorized"], False)

    def test_source_acceptance_cannot_authorize_distribution(self):
        source.validate_formal_v1(source.LEDGER.read_bytes())
        ledger, _ = source_v2.validate_ledger(source_v2.V2.read_bytes())
        self.assertIs(ledger["publicationAuthorized"], False)
        self.assertIs(ledger["distributionAuthorized"], False)
        self.assertEqual(ledger["formalDistribution"], "DENY")


if __name__ == "__main__":
    unittest.main()
