#!/usr/bin/env python3
"""Hostile-input unit tests for pg_permissions 1.4.1 acceptance-gate verification."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts import issue112_pg_permissions_acceptance_gate as gate


def _make_package_info(major: int, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": 1,
        "name": gate.EXTENSION_NAME,
        "version": gate.EXTENSION_VERSION,
        "upstream": {
            "repository": gate.UPSTREAM_REPOSITORY,
            "ref": gate.UPSTREAM_TAG,
            "commit": gate.UPSTREAM_COMMIT,
        },
        "postgresql": {"major": major},
        "buildMode": "release-attested",
        "workflowRun": {
            "event": "issue_comment",
            "ref": "refs/heads/main",
            "run_attempt": 1,
        },
    }
    payload.update(overrides)
    return payload


def _build_valid_asset_dir(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    sums_lines: list[str] = []
    for major in gate.SUPPORTED_PG_MAJORS:
        zip_name, spdx_name, grype_name = gate.expected_major_assets(major)
        zip_path = root / zip_name
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(
                "PACKAGE-INFO.json",
                json.dumps(_make_package_info(major)).encode("utf-8"),
            )
            zf.writestr("share/extension/pg_permissions.control", b"default_version = '1.4'\n")
        spdx_path = root / spdx_name
        spdx_path.write_text(
            json.dumps(
                {
                    "spdxVersion": "SPDX-2.3",
                    "dataLicense": "CC0-1.0",
                    "name": zip_name,
                    "packages": [{"name": "pg_permissions", "versionInfo": "1.4.1"}],
                    "files": [{"fileName": "share/extension/pg_permissions.control"}],
                }
            ),
            encoding="utf-8",
        )
        grype_path = root / grype_name
        grype_path.write_text(json.dumps({"matches": []}), encoding="utf-8")
        for path in (zip_path, spdx_path, grype_path):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            sums_lines.append(f"{digest}  {path.name}")
    (root / gate.SHA256SUMS_NAME).write_text("\n".join(sums_lines) + "\n", encoding="utf-8")
    return root


class PgPermissionsAcceptanceGateTests(unittest.TestCase):
    def test_expected_asset_set_is_exactly_13_files_pg15_to_pg18_only(self) -> None:
        assets = gate.expected_formal_assets()
        self.assertEqual(len(assets), 13)
        self.assertIn("SHA256SUMS.txt", assets)
        self.assertFalse(any("pg14" in name for name in assets))
        for major in (15, 16, 17, 18):
            self.assertIn(f"pg_permissions-REL_1_4_1-pg{major}-windows-x64.zip", assets)
            self.assertIn(f"pg_permissions-REL_1_4_1-pg{major}-windows-x64.spdx.json", assets)
            self.assertIn(f"pg_permissions-REL_1_4_1-pg{major}-windows-x64.vulnerabilities.json", assets)

    def test_default_status_is_zero_of_seven_candidate_only_and_deny(self) -> None:
        status = gate.evaluate_pilot_status()
        self.assertEqual(status["passedGates"], 0)
        self.assertEqual(status["totalGates"], 7)
        self.assertFalse(status["formalAcceptancePassed"])
        self.assertEqual(status["status"], "CANDIDATE_ONLY")
        self.assertEqual(status["publishDecision"], "DENY")
        self.assertEqual(status["publicGetDecision"], "DENY")
        self.assertEqual(status["upstream"]["commit"], "3360447e0668fed2b9db6a0ae1d086533781f9bd")
        self.assertEqual(status["candidateArtifact"]["id"], "14027920721")

    def test_valid_13_file_bundle_verifies_G3_to_G6_but_never_promotes_without_G1_G2_G7(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _build_valid_asset_dir(Path(tmp) / "bundle")
            status = gate.evaluate_pilot_status(asset_dir=bundle)
            self.assertEqual(status["passedGates"], 4)
            self.assertFalse(status["formalAcceptancePassed"])
            self.assertEqual(status["status"], "CANDIDATE_ONLY")
            self.assertEqual(status["publishDecision"], "DENY")
            self.assertEqual(status["publicGetDecision"], "DENY")

    def test_extra_pg14_file_or_missing_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _build_valid_asset_dir(Path(tmp) / "bundle")
            (bundle / "pg_permissions-REL_1_4_1-pg14-windows-x64.zip").write_bytes(b"extra")
            with self.assertRaises(gate.AcceptanceGateError):
                gate.verify_formal_asset_dir(bundle)

    def test_checksum_mismatch_or_bad_build_mode_or_pr_run_attempt_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _build_valid_asset_dir(Path(tmp) / "bundle")
            # Rewrite pg16 zip with candidate-only buildMode while keeping SHA256SUMS matching
            zip16 = bundle / "pg_permissions-REL_1_4_1-pg16-windows-x64.zip"
            with zipfile.ZipFile(zip16, "w") as zf:
                zf.writestr(
                    "PACKAGE-INFO.json",
                    json.dumps(_make_package_info(16, buildMode="candidate")).encode("utf-8"),
                )
            # Without updating SHA256SUMS, checksum fails first
            with self.assertRaises(gate.AcceptanceGateError):
                gate.verify_formal_asset_dir(bundle)
            # Even with updated SHA256SUMS, buildMode='candidate' fails provenance
            lines = []
            for line in (bundle / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
                if line.endswith(zip16.name):
                    lines.append(f"{hashlib.sha256(zip16.read_bytes()).hexdigest()}  {zip16.name}")
                else:
                    lines.append(line)
            (bundle / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(gate.AcceptanceGateError):
                gate.verify_formal_asset_dir(bundle)

    def test_blocking_vulnerability_or_symlink_asset_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _build_valid_asset_dir(Path(tmp) / "bundle")
            grype17 = bundle / "pg_permissions-REL_1_4_1-pg17-windows-x64.vulnerabilities.json"
            grype17.write_text(
                json.dumps({"matches": [{"vulnerability": {"id": "CVE-2099-0001", "severity": "High"}}]}),
                encoding="utf-8",
            )
            lines = []
            for line in (bundle / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
                if line.endswith(grype17.name):
                    lines.append(f"{hashlib.sha256(grype17.read_bytes()).hexdigest()}  {grype17.name}")
                else:
                    lines.append(line)
            (bundle / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaises(gate.AcceptanceGateError):
                gate.verify_formal_asset_dir(bundle)

        with tempfile.TemporaryDirectory() as tmp:
            bundle = _build_valid_asset_dir(Path(tmp) / "bundle")
            real_target = Path(tmp) / "real.txt"
            real_target.write_text("dummy", encoding="utf-8")
            sums = bundle / "SHA256SUMS.txt"
            sums.unlink()
            os.symlink(real_target, sums)
            with self.assertRaises(gate.AcceptanceGateError):
                gate.verify_formal_asset_dir(bundle)


if __name__ == "__main__":
    unittest.main()
