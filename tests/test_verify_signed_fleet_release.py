#!/usr/bin/env python3
"""Offline fail-closed Release byte, metadata, and operator provenance fixtures."""
import base64
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
    assets = [{"name": f.name, "state": "uploaded", "size": f.stat().st_size,
               "digest": "sha256:" + verifier.digest(f)} for f in root.iterdir()]
    return {"assets": assets}, manifest, contract, packaging


class SignedEvidenceTests(unittest.TestCase):
    def make(self, name="pg_hint_plan"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        return root, *fixture(root, name)

    def test_absent_first_release_stays_absent_without_published_attested_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "extensions"
            directory.mkdir()
            for name, version in (("pgtap", "1.3.4"),
                                  ("pg_variables", "1.2.1"),
                                  ("pg_store_plans", "1.10")):
                with self.subTest(extension=name):
                    target = directory / (name + ".json")
                    with patch.object(verifier, "api", return_value={
                        "tag_name": "v" + version + "-windows.1",
                        "draft": True, "prerelease": False,
                        "published_at": None
                    }):
                        with self.assertRaises(verifier.Denied):
                            verifier.generate(name, "v" + version + "-windows.1", target)
                    self.assertFalse(target.exists())

    def test_new_pg_repack_tag_denied_when_manifest_cannot_repin_postgresql_license(self):
        name = "pg_repack"
        repo = f"pgextwin/{name}"
        commit = "c" * 40
        tag = "v1.5.4-windows.1"
        manifest = {"name": name, "postgresql": {"majors": [15]},
                    "upstream": {"repository": "reorg/pg_repack", "version": "1.5.4",
                                 "ref": "ver_1.5.4", "commit": "d" * 40},
                    "license": {"files": [{"repositoryPath": "COPYRIGHT", "upstreamPath": "COPYRIGHT"}]}}
        contract = {"extension": name, "contractVersion": 2}
        release = {"tag_name": tag, "draft": False, "prerelease": False,
                   "published_at": "2026-11-21T11:30:00Z", "target_commitish": commit}
        old_tag = "v1.5.3-windows.2"
        original = json.dumps({
            "license": "PostgreSQL",
            "latest": {"releaseTag": old_tag, "publishedAt": "2026-10-20T12:00:00Z"},
            "releaseInventory": {"current": {"releaseTag": old_tag, "licensesByMajor": {
                "15": {"name": "PostgreSQL", "evidenceUrls": [
                    f"https://github.com/{repo}/blob/{'a' * 40}/COPYRIGHT",
                    f"https://github.com/postgres/postgres/blob/{'b' * 40}/COPYRIGHT",
                ]},
            }}},
        })
        lifecycle = {"postgresql": [{"major": major, "eol": "2030-01-01"} for major in range(14, 19)]}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "extensions"
            directory.mkdir()
            target = directory / f"{name}.json"
            target.write_text(original)
            with (patch.object(verifier, "api", side_effect=[release, {"status": "ahead"}, {
                      "encoding": "base64", "content": base64.b64encode(json.dumps(lifecycle).encode())}]),
                  patch.object(verifier, "verify_release_tag"),
                  patch.object(verifier, "pinned_json", side_effect=[manifest, contract]),
                  patch.object(verifier, "gh"),
                  patch.object(verifier, "verify_payload", return_value=({}, {}, 902, [None])),
                  patch.object(verifier, "verify_main_run"),
                  patch.object(verifier, "verify_release_attestations"),
                  patch.object(verifier, "map_verified_release") as mapper):
                with self.assertRaisesRegex(verifier.Denied,
                                            "no verified new license source for PG15: postgres/postgres/COPYRIGHT"):
                    verifier.generate(name, tag, target)
                mapper.assert_not_called()
            self.assertEqual(target.read_text(), original)

    def test_rollover_verifies_and_repins_packaging_and_per_major_upstream_license_files(self):
        _, _, manifest, _, commit = self.make()
        repo = "pgextwin/pg_hint_plan"
        upstream = "ossc-db/pg_hint_plan"
        previous = {str(major): {"name": "BSD", "evidenceUrls": [
            f"https://github.com/{repo}/blob/{'e' * 40}/NOTICE",
            f"https://github.com/{upstream}/blob/{'f' * 40}/LICENSE",
        ]} for major in (14, 15)}

        def load_file(route):
            path = route.split("/contents/")[1].split("?")[0]
            return {"type": "file", "path": path, "size": 100}

        with patch.object(verifier, "api", side_effect=load_file) as api:
            rows = verifier.verified_licenses(repo, commit, manifest, [14, 15], "BSD", previous)
        for major, upstream_commit in (("14", "a" * 40), ("15", "b" * 40)):
            self.assertEqual(rows[major]["evidenceUrls"], [
                f"https://github.com/{repo}/blob/{commit}/LICENSE",
                f"https://github.com/{repo}/blob/{commit}/NOTICE",
                f"https://github.com/{upstream}/blob/{upstream_commit}/LICENSE",
            ])
            api.assert_any_call(f"repos/{upstream}/contents/LICENSE?ref={upstream_commit}")
        api.assert_any_call(f"repos/{repo}/contents/NOTICE?ref={commit}")
        self.assertEqual(api.call_count, 3)

        with patch.object(verifier, "api", return_value={"type": "file", "path": "NOTICE", "size": 0}):
            with self.assertRaisesRegex(verifier.Denied, "version-specific license file missing"):
                verifier.verified_licenses(repo, commit, manifest, [14, 15], "BSD", previous)

    def test_exact_per_major_upstream_and_download_sha(self):
        root, release, manifest, contract, source = self.make()
        with (patch.object(verifier.hashlib, "sha256", wraps=hashlib.sha256) as sha256,
              patch.object(verifier, "read_package_info",
                           wraps=verifier.read_package_info) as read_info):
            assets, digests, run, packages = verifier.verify_payload(
                root, release, manifest, contract, source, [14, 15])
        self.assertEqual(run, 902)
        self.assertEqual(len(assets), 7)
        self.assertEqual(digests, {name: asset["digest"].removeprefix("sha256:")
                                   for name, asset in assets.items()})
        self.assertEqual(sha256.call_count, len(assets))
        self.assertEqual(read_info.call_count, 2)
        self.assertEqual([p.zip_path.name for p in packages],
                         ["pg_hint_plan-REL14_1_4_4-pg14-windows-x64.zip",
                          "pg_hint_plan-REL15_1_5_3-pg15-windows-x64.zip"])

    def test_orafce_nonstandard_upstream_ref(self):
        root, release, manifest, contract, source = self.make("orafce")
        _, digests, run, _ = verifier.verify_payload(
            root, release, manifest, contract, source, [14, 15])
        self.assertEqual(run, 902)
        self.assertIn("orafce-VERSION_4_16_13-pg14-windows-x64.zip", digests)

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
