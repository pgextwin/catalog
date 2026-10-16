#!/usr/bin/env python3
"""Issue #112: offline-only deterministic, hostile Manifest v1 contract tests."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from distribution_manifest_v1 import (
    ALLOWED, Denied, build_manifest, canonical, strict_json,
    validate_manifest, safe_path, verify_archive_members,
)

SCHEMA = json.loads((ROOT / "schema/distribution-manifest-v1.schema.json").read_text())
WHEN = "2026-10-16T02:00:00Z"
RELEASE_DATE = "2026-10-10T00:00:00Z"
MAJORS = ["14", "15", "16", "17", "18"]


def digest(s):
    return hashlib.sha256(s.encode()).hexdigest()


def fixtures():
    index = {"schemaVersion": 2, "extensions": sorted(ALLOWED)}
    data = {
        "index_blob": canonical(index), "catalog_commit": "a" * 40,
        "generated_at": WHEN, "record_blobs": {},
        "lifecycle": [{"major": int(m),
                       "eol": "2026-11-12" if m == "14" else "2030-11-14"}
                      for m in MAJORS],
        "approved_majors": MAJORS, "releases": {}, "pins": {}, "receipts": {},
        "independently_verify": lambda *args: True, "schema": SCHEMA,
    }
    for idx, name in enumerate(sorted(ALLOWED)):
        tag = "v1.0-windows.1"
        release_id = idx + 1000
        record = {
            "schemaVersion": 2, "name": name, "repository": "pgextwin/" + name,
            "architecture": "x64", "license": "BSD-3-Clause",
            "upstream": {"repository": ALLOWED[name], "version": "1.0"},
            "latest": {
                "releaseTag": tag, "publishedAt": RELEASE_DATE,
                "releaseUrl": "https://github.com/pgextwin/" + name + "/releases/tag/" + tag,
                "checksumsAsset": "SHA256SUMS.txt",
            },
            "postgresql": {},
            "runtime": {"requirements": {
                "extensionCreation": "required", "preload": "none",
                "backgroundWorker": False,
                "clientExecutable": {"required": name == "pg_repack",
                                     "packagePaths": ["bin/pg_repack.exe"] if name == "pg_repack" else []}
            }},
        }
        if name in ("pgaudit", "pg_hint_plan"):
            record["upstream"].pop("version")
            record["upstream"]["perPostgresql"] = {}
        assets = [{"name": "SHA256SUMS.txt", "id": 200000 + idx,
                   "state": "uploaded", "digest": "sha256:" + digest(name + ":sums")}]
        for m in MAJORS:
            version = m + ".1" if name in ("pgaudit", "pg_hint_plan") else "1.0"
            ref = "REL_" + m if name == "pg_hint_plan" else version
            if "perPostgresql" in record["upstream"]:
                record["upstream"]["perPostgresql"][m] = {"version": version, "ref": ref}
            stem = name + "-" + ref + "-pg" + m + "-windows-x64"
            base = "https://github.com/pgextwin/" + name + "/releases/download/" + tag + "/"
            key = (name, m)
            items = []
            for offset, suffix in enumerate((".zip", ".spdx.json", ".vulnerabilities.json")):
                filename = stem + suffix
                sha = digest(name + m + suffix)
                asset_id = idx * 1000 + int(m) * 10 + offset + 1
                assets.append({"name": filename, "id": asset_id,
                               "state": "uploaded", "digest": "sha256:" + sha,
                               "browser_download_url": base + filename})
                items.append({"available": True, "asset": filename,
                              "sha256": sha, "downloadUrl": base + filename})
            entry = dict(items[0])
            entry["evidence"] = {"sbom": items[1], "vulnerabilityReport": items[2]}
            record["postgresql"][m] = entry
            data["pins"][key] = {"version": version, "ref": ref, "commit": "b" * 40}
            data["receipts"][key] = {
                "assetId": assets[-3]["id"], "releaseId": release_id,
                "subjectSha256": items[0]["sha256"],
                "signerWorkflow": "pgextwin/build/.github/workflows/build-extension-attested.yml",
                "signerRepositoryId": 1405931353, "sourceRepositoryId": 1500000000 + idx,
                "trustedRootSha256": digest("authenticated-out-of-band-root"),
                "sourceRef": "refs/heads/main",
                "predicateTypes": ["https://slsa.dev/provenance/v1",
                                   "https://spdx.dev/Document/v2.3"],
                "attestationBundleName": stem + ".attestations.jsonl",
                "attestationBundleSha256": digest(stem + "provenance"),
                "sbomAttestationBundleName": stem + ".sbom-attestations.jsonl",
                "sbomAttestationBundleSha256": digest(stem + "sbom"),
                "verifiedAtUtc": WHEN,
            }
        data["record_blobs"][name] = canonical(record)
        data["releases"][name] = {
            "id": release_id, "tag_name": tag,
            "published_at": RELEASE_DATE, "draft": False, "prerelease": False,
            "target_commitish": "c" * 40, "assets": assets,
        }
    return data


def record_mutation(data, name, action):
    record = strict_json(data["record_blobs"][name])
    action(record)
    data["record_blobs"][name] = canonical(record)


def zip_of(entries):
    """Tuple entry=(filename, payload, optional ZipInfo)."""
    stream = io.BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        for filename, payload, info in entries:
            archive.writestr(info or filename, payload)
    stream.seek(0)
    return ZipFile(stream)


class ManifestV1Tests(unittest.TestCase):
    def assert_denied(self, data):
        with self.assertRaises(Denied):
            build_manifest(**data)

    def test_verified_fixture_covers_full_fleet(self):
        data = build_manifest(**fixtures())
        self.assertTrue(data["complete"])
        self.assertFalse(data["publicationAuthorized"])
        self.assertEqual(len(data["packages"]), 70)
        self.assertEqual(len(data["coverage"]), 70)
        self.assertTrue(validate_manifest(data, SCHEMA))
        self.assertEqual(set(p["evidence"]["status"] for p in data["packages"]),
                         {"SIGNATURE_VERIFIED"})

    def test_per_major_version_never_inferred_from_release_tag(self):
        data = build_manifest(**fixtures())
        for n in ("pgaudit", "pg_hint_plan"):
            rows = [p for p in data["packages"] if p["extension"] == n]
            self.assertEqual([p["packageVersion"] for p in rows],
                             [m + ".1" for m in MAJORS])
            self.assertEqual([p["upstreamRef"] for p in rows],
                             ["REL_" + m for m in MAJORS] if n == "pg_hint_plan"
                             else [m + ".1" for m in MAJORS])

    def test_repeatable_snapshot_id(self):
        d = fixtures()
        one = build_manifest(**d)
        two = build_manifest(**copy.deepcopy(d))
        self.assertEqual(canonical(one), canonical(two))
        self.assertEqual(one["snapshotId"], two["snapshotId"])

    def test_eol_day_transition_uses_utc(self):
        d = fixtures()
        d["generated_at"] = "2026-11-12T23:59:59Z"
        a = build_manifest(**d)
        self.assertEqual(sum(c["status"] == "historical" for c in a["coverage"]), 0)
        d["generated_at"] = "2026-11-13T00:00:00Z"
        b = build_manifest(**d)
        self.assertEqual(sum(c["status"] == "historical" for c in b["coverage"]), 14)
        self.assertTrue(b["complete"])

    def test_default_or_forged_verifier_not_accepted(self):
        d = fixtures()
        d["independently_verify"] = None
        self.assert_denied(d)
        d["independently_verify"] = lambda *args: False
        b = build_manifest(**d)
        self.assertFalse(b["complete"])
        self.assertEqual(len(b["packages"]), 0)
        self.assertTrue(all(x["status"] == "blocked" for x in b["coverage"]))

    def test_missing_verified_major_is_blocked_not_complete(self):
        d = fixtures()
        d["pins"].pop(("pgaudit", "14"))
        b = build_manifest(**d)
        self.assertEqual(len(b["packages"]), 69)
        self.assertFalse(b["complete"])
        self.assertIn({"extension": "pgaudit", "pgMajor": "14", "status": "blocked",
                       "reason": "independent signature and source pin required"},
                      b["coverage"])

    def test_missing_receipt_is_not_implicitly_verified(self):
        d = fixtures()
        d["receipts"].pop(("pg_cron", "18"))
        self.assertEqual(len(build_manifest(**d)["packages"]), 69)

    def test_strict_duplicate_json_keys(self):
        with self.assertRaises(Denied):
            strict_json('{"schemaVersion":2,"schemaVersion":99}')
        with self.assertRaises(Denied):
            strict_json('{"bad":NaN}')

    def test_wrong_pg19_requires_explicit_external_policy(self):
        d = fixtures()
        d["lifecycle"].append({"major": 19, "eol": "2031-11-01"})
        self.assert_denied(d)

    def test_untrusted_or_incomplete_catalog_rejected(self):
        for attack in ("missing", "reordered", "added"):
            d = fixtures()
            index = strict_json(d["index_blob"])
            if attack == "missing":
                index["extensions"].pop()
            elif attack == "reordered":
                index["extensions"].reverse()
            else:
                index["extensions"].append("attacker")
            d["index_blob"] = canonical(index)
            with self.subTest(attack=attack):
                self.assert_denied(d)

    def test_catalog_release_metadata_mismatch(self):
        for field, value in (("tag_name", "v99-windows.1"),
                             ("draft", True), ("prerelease", True),
                             ("published_at", "2026-10-11T00:00:00Z"),
                             ("target_commitish", "main"),
                             ("id", 0)):
            d = fixtures()
            d["releases"]["pgaudit"][field] = value
            with self.subTest(field=field):
                self.assert_denied(d)

    def test_other_repository_or_architecture_rejected(self):
        for field, value in (("repository", "attacker/pgaudit"),
                             ("architecture", "arm64")):
            d = fixtures()
            record_mutation(d, "pgaudit", lambda r: r.update({field: value}))
            with self.subTest(field=field):
                self.assert_denied(d)

    def test_digest_asset_replacement_denied(self):
        for field, value in (("digest", "sha256:" + "d"*64),
                             ("id", -1),
                             ("state", "uploaded-but-modified")):
            d = fixtures()
            assets = d["releases"]["pgaudit"]["assets"]
            next(a for a in assets if a["name"].endswith("-pg14-windows-x64.zip"))[field] = value
            with self.subTest(field=field):
                self.assert_denied(d)

    def test_duplicate_release_assets_denied(self):
        d = fixtures()
        assets = d["releases"]["pgaudit"]["assets"]
        assets.append(copy.deepcopy(assets[1]))
        self.assert_denied(d)

    def test_unverified_signature_repo_and_root_denied(self):
        attacks = [
            ("signerRepositoryId", 111),
            ("trustedRootSha256", "0"*64 + "x"),
            ("sourceRef", "refs/heads/attacker"),
            ("signerWorkflow", "attacker/workflow.yml"),
            ("predicateTypes", ["https://slsa.dev/provenance/v1"]),
            ("assetId", 1),
            ("subjectSha256", "d"*64),
            ("attestationBundleSha256", "incorrect"),
        ]
        for field, value in attacks:
            d = fixtures()
            d["receipts"][("pgaudit", "14")][field] = value
            with self.subTest(field=field):
                self.assert_denied(d)

    def test_modified_upstream_ref_and_wrong_pg_asset_denied(self):
        d = fixtures()
        d["pins"][("pg_hint_plan", "14")]["ref"] = "REL_18"
        self.assert_denied(d)
        d = fixtures()
        record_mutation(d, "pgaudit",
                        lambda r: r["postgresql"]["14"].update(
                            asset=r["postgresql"]["18"]["asset"]))
        self.assert_denied(d)

    def test_unsafe_paths_and_windows_aliases_denied(self):
        for value in ("/root/file.zip", "../file.zip", "a/../file.zip",
                      r"a\b.zip", "C:/Windows/file.zip", "a//b.zip",
                      "a/CON", "a/com1.txt", "a/trailing.", "a/%2e%2e",
                      "a/evil:file"):
            with self.subTest(path=value):
                with self.assertRaises(Denied):
                    safe_path(value)

    def test_manifest_self_substitution_denied(self):
        b = build_manifest(**fixtures())
        for attack in ("digest", "coverage", "root", "published"):
            m = copy.deepcopy(b)
            if attack == "digest":
                m["packages"][0]["releaseAssetSha256"] = "f"*64
            if attack == "coverage":
                m["coverage"][0]["status"] = "unsupported"
            if attack == "root":
                m["trust"]["offlineTrustRoot"] = "FROM_BUNDLE"
            if attack == "published":
                m["publicationAuthorized"] = True
            with self.subTest(attack=attack), self.assertRaises(Denied):
                validate_manifest(m, SCHEMA)

    def test_unknown_manifest_key_denied(self):
        b = build_manifest(**fixtures())
        b["publisherToken"] = "surprise"
        with self.assertRaises(Denied):
            validate_manifest(b, SCHEMA)

    def test_zip_safe(self):
        with zip_of([("PACKAGE-INFO.json", b"{}"),
                     ("lib/ext.dll", b"x"*10000)]) as z:
            self.assertEqual(verify_archive_members(z), 2)

    def test_zip_traversal_absolute_and_windows_path(self):
        for path in ("../../evil.txt", "/etc/passwd", r"C:\boot.ini",
                     "lib/../evil", "a//b", "lib/CON.txt"):
            with zip_of([(path, b"evil")]) as z:
                with self.subTest(path=path), self.assertRaises(Denied):
                    verify_archive_members(z)

    def test_zip_case_insensitive_duplicate(self):
        with zip_of([("readme.txt", b"a"), ("README.TXT", b"b")]) as z:
            with self.assertRaises(Denied):
                verify_archive_members(z)

    def test_zip_symlink_denied(self):
        info = ZipInfo("lib/escape")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        with zip_of([("lib/escape", b"../../target", info)]) as z:
            with self.assertRaises(Denied):
                verify_archive_members(z)

    def test_zip_bomb_ratio_denied(self):
        with zip_of([("lib/compressed.dll", b"\0" * 2_000_000)]) as z:
            with self.assertRaises(Denied):
                verify_archive_members(z)

    def test_zip_file_directory_collision_denied(self):
        with zip_of([("lib", b"x"), ("lib/x.dll", b"y")]) as z:
            with self.assertRaises(Denied):
                verify_archive_members(z)


if __name__ == "__main__":
    unittest.main()
