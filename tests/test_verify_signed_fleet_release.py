#!/usr/bin/env python3
"""Offline fail-closed Release byte, metadata, and operator provenance fixtures."""
import copy
from datetime import date
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from scripts import verify_signed_fleet_release as verifier


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture(root, name="pg_hint_plan", second_run=902):
    packaging = "c" * 40
    if name == "pg_hint_plan":
        per = {
            "14": {"ref": "REL14_1_4_4", "version": "1.4.4", "commit": "a"*40},
            "15": {"ref": "REL15_1_5_3", "version": "1.5.3", "commit": "b"*40},
        }
        up = {"repository": "ossc-db/pg_hint_plan", "perPostgresql": per}
    else:
        up = {"repository": "orafce/orafce", "ref": "VERSION_4_16_13",
              "version": "4.16.13", "commit": "a"*40}
    repo = "pgextwin/" + name
    manifest = {"name": name, "upstream": up, "postgresql": {"majors": [14, 15]}}
    contract = {"contractVersion": 2, "extension": name,
                "runtimeRequirements": {"backgroundWorker": False},
                "coverage": {}, "functionalScenarios": []}
    for m in (14, 15):
        s = up["perPostgresql"][str(m)] if "perPostgresql" in up else up
        prefix = name + "-" + s["ref"] + "-pg" + str(m) + "-windows-x64"
        pkg = {"schemaVersion": 1, "buildMode": "release-attested",
               "package": {"name": name, "platform": "windows", "architecture": "x64"},
               "upstream": {"repository": up["repository"], "ref": s["ref"],
                            "version": s["version"], "commit": s["commit"]},
               "source": {"packagingRepository": repo, "packagingCommit": packaging},
               "postgresql": {"major": m},
               "workflowRun": {"id": second_run, "ref": "refs/heads/main",
                               "event": "workflow_dispatch"}}
        with ZipFile(root / (prefix + ".zip"), "w") as zipped:
            zipped.writestr("PACKAGE-INFO.json", json.dumps(pkg))
        (root / (prefix + ".spdx.json")).write_text(json.dumps({"spdxVersion": "SPDX-2.3"}))
        (root / (prefix + ".vulnerabilities.json")).write_text(json.dumps({"matches": []}))
    names = sorted(p.name for p in root.iterdir())
    sums = {n: verifier.digest(root / n) for n in names}
    (root / "SHA256SUMS.txt").write_text(
        "".join(v + "  " + k + "\n" for k, v in sorted(sums.items())))
    assets = [{"name": f.name, "state": "uploaded",
               "digest": "sha256:" + verifier.digest(f)} for f in root.iterdir()]
    return {"assets": assets}, manifest, contract, packaging


class SignedEvidenceTests(unittest.TestCase):
    def make(self, name="pg_hint_plan"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        return root, *fixture(root, name)

    def test_exact_per_major_upstream_and_download_sha(self):
        root, release, manifest, contract, source = self.make()
        assets, sums, run = verifier.verify_payload(
            root, release, manifest, contract, source, [14, 15])
        self.assertEqual(run, 902)
        self.assertEqual(len(assets), 7)
        self.assertEqual(len(sums), 6)
        self.assertIn("pg_hint_plan-REL14_1_4_4-pg14-windows-x64.zip", sums)
        self.assertIn("pg_hint_plan-REL15_1_5_3-pg15-windows-x64.zip", sums)

    def test_orafce_nonstandard_upstream_ref(self):
        root, release, manifest, contract, source = self.make("orafce")
        assets, sums, run = verifier.verify_payload(
            root, release, manifest, contract, source, [14, 15])
        self.assertEqual(run, 902)
        self.assertIn("orafce-VERSION_4_16_13-pg14-windows-x64.zip", sums)

    def test_denies_tampered_asset_even_with_good_checksum(self):
        root, release, manifest, contract, source = self.make()
        release["assets"][0]["digest"] = "sha256:" + "0"*64
        with self.assertRaises(verifier.Denied):
            verifier.verify_payload(root, release, manifest, contract, source, [14, 15])

    def test_denies_incomplete_major_matrix(self):
        root, release, manifest, contract, source = self.make()
        with self.assertRaises(verifier.Denied):
            verifier.verify_payload(root, release, manifest, contract, source, [14])

    def test_denies_extra_untrusted_download_file(self):
        root, release, manifest, contract, source = self.make()
        (root / "injected.zip").write_bytes(b"x")
        with self.assertRaises(verifier.Denied):
            verifier.verify_payload(root, release, manifest, contract, source, [14, 15])

    def test_denies_corrupt_spdx_after_hashes_are_recalculated(self):
        root, release, manifest, contract, source = self.make()
        file = next(root.glob("*.spdx.json"))
        file.write_text('{"spdxVersion":"SPDX-9"}')
        names = sorted(p.name for p in root.iterdir() if p.name != "SHA256SUMS.txt")
        sums = {n: verifier.digest(root / n) for n in names}
        (root / "SHA256SUMS.txt").write_text(
            "".join(v + "  " + k + "\n" for k, v in sorted(sums.items())))
        for a in release["assets"]:
            a["digest"] = "sha256:" + verifier.digest(root / a["name"])
        with self.assertRaises(verifier.Denied):
            verifier.verify_payload(root, release, manifest, contract, source, [14, 15])

    def test_source_identity_always_exact(self):
        pkg = {"schemaVersion": 1, "buildMode": "release-attested",
               "package": {"name": "orafce", "platform": "windows", "architecture": "x64"},
               "upstream": {"repository": "orafce/orafce", "ref": "VERSION_4_16_13",
                            "version": "4.16.13", "commit": "a"*40},
               "source": {"packagingRepository": "pgextwin/orafce",
                          "packagingCommit": "c"*40},
               "postgresql": {"major": 15},
               "workflowRun": {"id": 902, "ref": "refs/heads/main",
                               "event": "workflow_dispatch"}}
        source = {"repository": "orafce/orafce", "ref": "VERSION_4_16_13",
                  "version": "4.16.13", "commit": "a"*40}
        self.assertEqual(verifier.check_source_package(pkg, "pgextwin/orafce",
                                                       "c"*40, 15, source), 902)
        for change in (
            lambda p: p["upstream"].update(commit="b"*40),
            lambda p: p["upstream"].update(ref="attacker"),
            lambda p: p["source"].update(packagingCommit="e"*40),
            lambda p: p["workflowRun"].update(event="push"),
            lambda p: p["workflowRun"].update(ref="refs/heads/release/unsafe"),
            lambda p: p.update(buildMode="candidate"),
        ):
            with self.subTest(change=change):
                altered = copy.deepcopy(pkg)
                change(altered)
                with self.assertRaises(verifier.Denied):
                    verifier.check_source_package(altered, "pgextwin/orafce",
                                                  "c"*40, 15, source)

    def test_manual_run_must_be_main_operator_and_success(self):
        run = {"head_sha": "c"*40, "head_branch": "main",
               "event": "workflow_dispatch",
               "path": ".github/workflows/promote.yml",
               "actor": {"login": "trusted-operator"},
               "status": "completed", "conclusion": "success"}
        with patch.object(verifier, "api", return_value=run):
            verifier.verify_main_run("pgextwin/orafce", 902, "c"*40)
        for key, wrong in (("head_sha", "a"*40), ("event", "push"),
                           ("conclusion", "failure"),
                           ("path", "pgextwin/orafce/.github/workflows/promote.yml"),
                           ("path", ".github/workflows/windows.yml"),
                           ("path", ".github/workflows/promote.yml@refs/heads/main")):
            bad = copy.deepcopy(run)
            bad[key] = wrong
            with patch.object(verifier, "api", return_value=bad):
                with self.assertRaises(verifier.Denied):
                    verifier.verify_main_run("pgextwin/orafce", 902, "c"*40)
        bad = copy.deepcopy(run)
        bad["actor"]["login"] = "github-actions[bot]"
        with patch.object(verifier, "api", return_value=bad):
            with self.assertRaises(verifier.Denied):
                verifier.verify_main_run("pgextwin/orafce", 902, "c"*40)

    def test_postgresql_eol_disables_new_release_major_not_history(self):
        manifest = {"postgresql": {"majors": [14, 15, 16, 17, 18]}}
        lifecycle = {"postgresql": [{"major": m, "eol": "2026-11-12" if m == 14
                                     else "2030-11-14"} for m in range(14, 19)]}
        self.assertEqual(verifier.required_majors(
            manifest, lifecycle, date(2026, 11, 12)), [14, 15, 16, 17, 18])
        self.assertEqual(verifier.required_majors(
            manifest, lifecycle, date(2026, 11, 13)), [15, 16, 17, 18])

    def test_release_major_matrix_uses_publication_day_not_sync_day(self):
        manifest = {"postgresql": {"majors": [14, 15, 16, 17, 18]}}
        lifecycle = {"postgresql": [
            {"major": m, "eol": "2026-11-12" if m == 14 else "2030-11-14"}
            for m in range(14, 19)
        ]}
        pre_eol_release = {"published_at": "2026-11-12T23:59:00Z"}
        post_eol_release = {"published_at": "2026-11-13T00:01:00Z"}
        self.assertEqual(
            verifier.required_majors(
                manifest, lifecycle, verifier.published_release_day(pre_eol_release)),
            [14, 15, 16, 17, 18])
        self.assertEqual(
            verifier.required_majors(
                manifest, lifecycle, verifier.published_release_day(post_eol_release)),
            [15, 16, 17, 18])
        # Even if the Catalog proposal happens days later, the signed
        # Release's actual PG14 payload remains valid historical evidence.
        self.assertEqual(
            verifier.published_release_day(pre_eol_release), date(2026, 11, 12))

    def test_release_publication_timestamp_must_have_timezone(self):
        for stamp in ("invalid", "2026-11-12T23:59:00"):
            with self.subTest(stamp=stamp):
                with self.assertRaises(verifier.Denied):
                    verifier.published_release_day({"published_at": stamp})

    def test_denies_replayed_or_unknown_tag_commit(self):
        with patch.object(verifier, "api", return_value={
            "object": {"type": "commit", "sha": "a"*40}
        }):
            with self.assertRaises(verifier.Denied):
                verifier.verify_release_tag("pgextwin/orafce", "v4.16.13-windows.2",
                                            "b"*40)


    def test_catalog_downgrade_and_same_timestamp_replay_denied(self):
        existing = {"latest": {"releaseTag": "v2.10.15-windows.1",
                               "publishedAt": "2026-10-12T12:00:00Z"}}
        release = {"tag_name": "v2.10.14-windows.1",
                   "published_at": "2026-10-11T12:00:00Z"}
        with self.assertRaises(verifier.Denied):
            verifier.deny_catalog_rollback(existing, release)
        release["published_at"] = "2026-10-12T12:00:00Z"
        with self.assertRaises(verifier.Denied):
            verifier.deny_catalog_rollback(existing, release)
        release["tag_name"] = "v2.10.15-windows.1"
        verifier.deny_catalog_rollback(existing, release)
        release["tag_name"] = "v2.10.16-windows.1"
        release["published_at"] = "2026-10-13T12:00:00Z"
        verifier.deny_catalog_rollback(existing, release)


if __name__ == "__main__":
    unittest.main()
