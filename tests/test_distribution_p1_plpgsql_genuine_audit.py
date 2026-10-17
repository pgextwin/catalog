#!/usr/bin/env python3
"""Read-only original recovery pilot guard tests, no live network or trust claim."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from distribution_manifest_v1 import Denied
import distribution_p1_plpgsql_genuine_audit as audit


class OriginalAuditGuards(unittest.TestCase):
    def test_only_exact_original_seven_transport_zip_get_paths(self):
        with patch.object(audit.subprocess, "run",
                          side_effect=AssertionError("no unauthorized process")):
            for path in (
                "repos/pgextwin/plpgsql_check/actions/artifacts/11698050284",
                "repos/pgextwin/plpgsql_check/actions/artifacts/11698050284/zip/delete",
                "repos/pgextwin/plpgsql_check/actions/artifacts/999/zip",
                "repos/pgextwin/orafce/actions/artifacts/11698050284/zip",
                "repos/pgextwin/plpgsql_check/actions/artifacts/11698050284/zip?method=PATCH",
                "repos/pgextwin/plpgsql_check/actions/runs/38128142145/rerun",
            ):
                with self.subTest(path=path), self.assertRaises(Denied):
                    audit.official_original_get_bytes(path)

    def test_run_get_allowlist_never_dispatches_or_reruns(self):
        with patch.object(audit.subprocess, "run",
                          side_effect=AssertionError("no unauthorized process")):
            for path in (
                "repos/pgextwin/plpgsql_check/actions/runs/38128142145",
                "repos/pgextwin/plpgsql_check/actions/runs/38128142145/attempts/2",
                "repos/pgextwin/plpgsql_check/actions/runs/38128142145/rerun",
                "repos/pgextwin/plpgsql_check/actions/runs/999/attempts/1",
                "repos/pgextwin/plpgsql_check/actions/runs/38128142145/attempts/1/jobs?per_page=100&page=2",
            ):
                with self.subTest(path=path), self.assertRaises(Denied):
                    audit.read_original_json(path)

    def test_no_formal_acceptance_without_real_original_and_event(self):
        with patch.object(audit, "policy_load", side_effect=Denied("no sealed P1 policy")):
            with self.assertRaises(Denied):
                audit.execute()


if __name__ == "__main__":
    unittest.main()
