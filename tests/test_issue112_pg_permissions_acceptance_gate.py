#!/usr/bin/env python3
"""Hostile-input unit tests for pg_permissions 1.4.1 acceptance-gate verification."""

from __future__ import annotations

import contextlib
import hashlib
import io
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
        "buildMode": "release-attested",
        "package": {
            "name": gate.EXTENSION_NAME,
            "platform": "windows",
            "architecture": "x64",
        },
        "upstream": {
            "repository": gate.UPSTREAM_REPOSITORY,
            "ref": gate.UPSTREAM_TAG,
            "version": gate.EXTENSION_VERSION,
            "commit": gate.UPSTREAM_COMMIT,
        },
        "source": {
            "packagingRepository": gate.PACKAGING_REPOSITORY,
            "packagingCommit": "771571c390133bf98f3d84561cee889fba16f3d7",
        },
        "postgresql": {"major": major},
        "workflowRun": {
            "id": 43752228957,
            "attempt": 1,
            "event": "issue_comment",
            "ref": "refs/heads/main",
        },
    }
    payload.update(overrides)
    return payload


def _make_spdx(zip_name: str, *, include_files: bool = False) -> dict[str, object]:
    doc: dict[str, object] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": zip_name.removesuffix(".zip"),
        "packages": [
            {
                "name": zip_name.removesuffix(".zip"),
                "versionInfo": gate.EXTENSION_VERSION,
                "filesAnalyzed": include_files,
            }
        ],
    }
    if include_files:
        doc["files"] = [{"fileName": "share/extension/pg_permissions.control"}]
    return doc


def _build_valid_asset_dir(root: Path, *, include_sums: bool = True) -> Path:
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
        spdx_path.write_text(json.dumps(_make_spdx(zip_name)), encoding="utf-8")
        grype_path = root / grype_name
        grype_path.write_text(json.dumps({"matches": []}), encoding="utf-8")
        for path in (zip_path, spdx_path, grype_path):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            sums_lines.append(f"{digest}  {path.name}")
    if include_sums:
        (root / gate.SHA256SUMS_NAME).write_text("\n".join(sums_lines) + "\n", encoding="utf-8")
    return root


def _rehash_sums(bundle: Path, target_name: str) -> None:
    target = bundle / target_name
    lines = []
    for line in (bundle / gate.SHA256SUMS_NAME).read_text(encoding="utf-8").splitlines():
        if line.endswith(target_name):
            lines.append(f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target_name}")
        else:
            lines.append(line)
    (bundle / gate.SHA256SUMS_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")


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

    def test_untrusted_boolean_gate_evidence_is_rejected_even_with_assets(self) -> None:
        all_true = {gate_id: True for gate_id in gate.GATE_IDS}
        with self.assertRaises(gate.AcceptanceGateError):
            gate.evaluate_pilot_status(gate_evidence=all_true)
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _build_valid_asset_dir(Path(tmp) / "bundle")
            with self.assertRaises(gate.AcceptanceGateError):
                gate.evaluate_pilot_status(gate_evidence=all_true, asset_dir=bundle)
            diagnostic = gate.evaluate_pilot_status(asset_dir=bundle)
            self.assertEqual(diagnostic["passedGates"], 0)
            self.assertEqual(diagnostic["totalGates"], 7)
            self.assertFalse(diagnostic["formalAcceptancePassed"])
            self.assertEqual(diagnostic["publishDecision"], "DENY")
            self.assertEqual(diagnostic["publicGetDecision"], "DENY")
            self.assertEqual(diagnostic["assetReport"]["assetCount"], 13)

    def test_valid_13_file_bundle_is_diagnostic_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _build_valid_asset_dir(Path(tmp) / "bundle")
            status = gate.evaluate_pilot_status(asset_dir=bundle)
            self.assertEqual(status["passedGates"], 0)
            self.assertFalse(status["formalAcceptancePassed"])
            self.assertEqual(status["status"], "CANDIDATE_ONLY")
            self.assertEqual(status["publishDecision"], "DENY")
            self.assertEqual(status["publicGetDecision"], "DENY")
            self.assertEqual(status["assetReport"]["majors"][15]["spdx"]["fileCount"], 0)

    def test_12_file_bundle_without_sha256sums_keeps_diagnostic_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _build_valid_asset_dir(Path(tmp) / "bundle", include_sums=False)
            self.assertFalse((bundle / gate.SHA256SUMS_NAME).exists())
            status = gate.evaluate_pilot_status(asset_dir=bundle)
            self.assertEqual(status["passedGates"], 0)
            self.assertEqual(status["assetReport"]["assetCount"], 13)
            self.assertFalse((bundle / gate.SHA256SUMS_NAME).exists())

            (bundle / "pg_permissions-REL_1_4_1-pg18-windows-x64.zip").unlink()
            with self.assertRaises(gate.AcceptanceGateError):
                gate.verify_formal_asset_dir(bundle)

    def test_extra_pg14_file_or_missing_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _build_valid_asset_dir(Path(tmp) / "bundle")
            (bundle / "pg_permissions-REL_1_4_1-pg14-windows-x64.zip").write_bytes(b"extra")
            with self.assertRaises(gate.AcceptanceGateError):
                gate.verify_formal_asset_dir(bundle)

    def test_checksum_mismatch_or_bad_build_mode_or_pr_run_attempt_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _build_valid_asset_dir(Path(tmp) / "bundle")
            zip16 = bundle / "pg_permissions-REL_1_4_1-pg16-windows-x64.zip"
            with zipfile.ZipFile(zip16, "w") as zf:
                zf.writestr(
                    "PACKAGE-INFO.json",
                    json.dumps(_make_package_info(16, buildMode="candidate")).encode("utf-8"),
                )
            with self.assertRaises(gate.AcceptanceGateError):
                gate.verify_formal_asset_dir(bundle)
            _rehash_sums(bundle, zip16.name)
            with self.assertRaises(gate.AcceptanceGateError):
                gate.verify_formal_asset_dir(bundle)

    def test_nested_package_info_malformed_fields_fail_closed(self) -> None:
        bad_payloads = [
            _make_package_info(15, schemaVersion=2),
            _make_package_info(15, schemaVersion=True),
            _make_package_info(15, package={"name": "other_ext"}),
            _make_package_info(
                15,
                upstream={
                    "repository": gate.UPSTREAM_REPOSITORY,
                    "ref": gate.UPSTREAM_TAG,
                    "version": "1.4.0",
                    "commit": gate.UPSTREAM_COMMIT,
                },
            ),
            _make_package_info(15, source={"packagingCommit": "not-a-sha"}),
            _make_package_info(
                15,
                workflowRun={
                    "id": 43752228957,
                    "attempt": 2,
                    "event": "issue_comment",
                    "ref": "refs/heads/main",
                },
            ),
            _make_package_info(
                15,
                workflowRun={
                    "id": 0,
                    "attempt": 1,
                    "event": "issue_comment",
                    "ref": "refs/heads/main",
                },
            ),
            {
                "name": gate.EXTENSION_NAME,
                "version": gate.EXTENSION_VERSION,
                "upstream": {
                    "repository": gate.UPSTREAM_REPOSITORY,
                    "ref": gate.UPSTREAM_TAG,
                    "commit": gate.UPSTREAM_COMMIT,
                },
                "postgresql": {"major": 15},
                "buildMode": "release-attested",
                "workflowRun": {"event": "issue_comment", "ref": "refs/heads/main", "run_attempt": 1},
            },
        ]
        for payload in bad_payloads:
            with tempfile.TemporaryDirectory() as tmp:
                bundle = _build_valid_asset_dir(Path(tmp) / "bundle", include_sums=False)
                zip15 = bundle / "pg_permissions-REL_1_4_1-pg15-windows-x64.zip"
                with zipfile.ZipFile(zip15, "w") as zf:
                    zf.writestr("PACKAGE-INFO.json", json.dumps(payload).encode("utf-8"))
                with self.assertRaises(gate.AcceptanceGateError):
                    gate.verify_formal_asset_dir(bundle)

    def test_spdx_package_level_and_file_level_and_invalid_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = _build_valid_asset_dir(Path(tmp) / "bundle", include_sums=False)
            spdx15 = bundle / "pg_permissions-REL_1_4_1-pg15-windows-x64.spdx.json"
            zip15_name = "pg_permissions-REL_1_4_1-pg15-windows-x64.zip"

            # File-level SPDX with 1 package and non-empty files passes
            spdx15.write_text(json.dumps(_make_spdx(zip15_name, include_files=True)), encoding="utf-8")
            report = gate.verify_formal_asset_dir(bundle)
            self.assertEqual(report["majors"][15]["spdx"]["fileCount"], 1)

            # Missing files when filesAnalyzed is True fails closed
            bad_doc = _make_spdx(zip15_name, include_files=True)
            del bad_doc["files"]
            spdx15.write_text(json.dumps(bad_doc), encoding="utf-8")
            with self.assertRaises(gate.AcceptanceGateError):
                gate.verify_formal_asset_dir(bundle)

            # Two packages fails closed even with filesAnalyzed=false
            two_pkgs = _make_spdx(zip15_name, include_files=False)
            two_pkgs["packages"] = [
                {"name": "pkg1", "filesAnalyzed": False},
                {"name": "pkg2", "filesAnalyzed": False},
            ]
            spdx15.write_text(json.dumps(two_pkgs), encoding="utf-8")
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
            _rehash_sums(bundle, grype17.name)
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

    def test_cli_verify_assets_and_evidence_option(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bundle = _build_valid_asset_dir(tmp_path / "bundle")

            # Structure inspection does not authenticate any G1-G7 gate
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = gate.main(["--verify-assets", str(bundle)])
            self.assertEqual(rc, 0)
            report = json.loads(stdout.getvalue())
            self.assertEqual(report["passedGates"], 0)
            self.assertFalse(report["gates"]["G1_PIN_CHAIN_CENTRAL_REG"])
            self.assertFalse(report["gates"]["G2_PROTECTED_MAIN_AND_OWNER_SIGN"])
            self.assertFalse(report["gates"]["G7_SCOPED_PUBLISHER_ADMISSION"])
            self.assertEqual(report["publishDecision"], "DENY")

            # Caller-supplied boolean evidence is never a grant of authority
            evidence_path = tmp_path / "evidence.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "G1_PIN_CHAIN_CENTRAL_REG": True,
                        "G2_PROTECTED_MAIN_AND_OWNER_SIGN": True,
                        "G7_SCOPED_PUBLISHER_ADMISSION": True,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(gate.AcceptanceGateError):
                gate.main(["--verify-assets", str(bundle), "--evidence", str(evidence_path)])

            # Non-boolean evidence value or symlinked evidence file fails closed
            bad_evidence = tmp_path / "bad_evidence.json"
            bad_evidence.write_text(json.dumps({"G1_PIN_CHAIN_CENTRAL_REG": "true"}), encoding="utf-8")
            with self.assertRaises(gate.AcceptanceGateError):
                gate.main(["--evidence", str(bad_evidence)])

            sym_evidence = tmp_path / "sym_evidence.json"
            os.symlink(evidence_path, sym_evidence)
            with self.assertRaises(gate.AcceptanceGateError):
                gate.main(["--evidence", str(sym_evidence)])


if __name__ == "__main__":
    unittest.main()
