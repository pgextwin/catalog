#!/usr/bin/env python3
"""P1 synthetic offline hostile regressions; fixtures ARE NOT Sigstore proof."""
from __future__ import annotations
import copy
from hashlib import sha256
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile, ZIP_DEFLATED

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import distribution_release_verify_p1 as p1
from distribution_manifest_v1 import Denied, canonical


def digest(b):
    return sha256(b).hexdigest()


def record(name="example", major="19"):
    return {
        "schemaVersion": 2, "name": name, "repository": "pgextwin/" + name,
        "architecture": "x64", "upstream": {"repository": "upstream/" + name, "version": "3.0"},
        "latest": {"releaseTag": "v3-windows.1", "publishedAt": "2026-11-30T01:00:00Z",
                   "releaseUrl": "https://github.com/pgextwin/" + name
                                 + "/releases/tag/v3-windows.1"},
        "postgresql": {major: {"available": True}},
    }


def source(name="example", majors=(19,)):
    return {
        "name": name, "postgresql": {"majors": list(majors)},
        "upstream": {"repository": "upstream/" + name, "version": "3.0",
                     "ref": "3.0", "commit": "b"*40},
    }


def make_release(name="example", major="19"):
    stem = name + "-3.0-pg" + major + "-windows-x64"
    assets = {}
    for suffix in (".zip", ".spdx.json", ".vulnerabilities.json"):
        assets[stem + suffix] = b"pretend " + suffix.encode()
    sums = "".join(digest(blob) + "  " + n + "\n" for n, blob in assets.items()).encode()
    assets["SHA256SUMS.txt"] = sums
    repo = "pgextwin/" + name
    release = {
        "id": 4001, "tag_name": "v3-windows.1",
        "published_at": "2026-11-30T01:00:00Z",
        "draft": False, "prerelease": False, "target_commitish": "a"*40,
        "html_url": "https://github.com/" + repo + "/releases/tag/v3-windows.1",
        "assets": [],
    }
    for i, (n, blob) in enumerate(assets.items(), 1):
        release["assets"].append({
            "id": i, "name": n, "size": len(blob), "state": "uploaded",
            "digest": "sha256:" + digest(blob),
            "browser_download_url": "https://github.com/" + repo
                                     + "/releases/download/v3-windows.1/" + n,
        })
    entry = record(name, major)["postgresql"][major]
    entry.update(asset=stem+".zip", sha256=digest(assets[stem+".zip"]),
                 evidence={
                     "sbom": {"available": True, "asset": stem+".spdx.json",
                              "sha256": digest(assets[stem+".spdx.json"])},
                     "vulnerabilityReport": {
                         "available": True, "asset": stem+".vulnerabilities.json",
                         "sha256": digest(assets[stem+".vulnerabilities.json"])},
                 })
    r = record(name, major)
    r["postgresql"][major] = entry
    return r, release, assets


def cert_fixture(repo="pgextwin/example", rid=7001, attempt=1):
    filename = "example-3.0-pg19-windows-x64.zip"
    hash_value = "a"*64
    run_uri = f"https://github.com/{repo}/actions/runs/567/attempts/{attempt}"
    signer_sha = "b"*40
    signer = "https://github.com/pgextwin/build/.github/workflows/build-extension-attested.yml@" + signer_sha
    sbom = {"spdxVersion": "SPDX-2.3"}
    c = {
        "issuer": p1.ISSUER, "sourceRepositoryURI": "https://github.com/" + repo,
        "sourceRepositoryIdentifier": str(rid), "sourceRepositoryDigest": "a"*40,
        "sourceRepositoryRef": "refs/heads/main", "runInvocationURI": run_uri,
        "buildTrigger": "workflow_dispatch", "buildSignerURI": signer,
        "subjectAlternativeName": signer, "buildSignerDigest": signer_sha,
        "githubWorkflowSHA": "a"*40, "githubWorkflowRef": "refs/heads/main",
    }
    result = [{
        "verificationResult": {
            "signature": {"certificate": c}, "verifiedTimestamps": [{"logIndex": 1}],
            "statement": {"predicateType": p1.SPDX,
                          "subject": [{"name": filename, "digest": {"sha256": hash_value}}],
                          "predicate": sbom},
        }
    }]
    kwargs = dict(predicate=p1.SPDX, name=filename, digest=hash_value, sbom=sbom,
                  repository=repo, repository_id=rid, packaging_sha="a"*40,
                  signer_sha=signer_sha, run_id=567, attempt=attempt)
    return result, kwargs


class P1Tests(unittest.TestCase):
    def deny(self, f, *args, **kwargs):
        with self.assertRaises(Denied):
            f(*args, **kwargs)

    def test_dynamic_15th_extension_catalog(self):
        names = ["extra" + str(i) for i in range(15)]
        blobs = {n: canonical(record(n)) for n in names}
        ib = canonical({"schemaVersion": 2, "extensions": names})
        pins = {"index.json": digest(ib)}
        pins.update({"extensions/" + n + ".json": digest(blob) for n, blob in blobs.items()})
        result = p1.verified_catalog(ib, blobs, pins, "c"*40)
        self.assertEqual(len(result), 15)
        self.assertEqual(len(p1.fleet_counts(result, {})["reasons"]), 0)
        self.assertEqual(p1.fleet_counts(result, {})["expected"], 15)
        self.assertFalse(p1.fleet_counts(result, {})["complete"])

    def test_catalog_rejects_missing_or_tampered_blob(self):
        names = ["extra1", "extra2"]
        blobs = {n: canonical(record(n)) for n in names}
        ib = canonical({"schemaVersion": 2, "extensions": names})
        pins = {"index.json": digest(ib)}
        pins.update({"extensions/" + n + ".json": digest(blob) for n, blob in blobs.items()})
        for attack in ("missing", "tamper", "extra", "index"):
            data = copy.deepcopy(blobs)
            policy = dict(pins)
            if attack == "missing":
                data.pop("extra1")
            if attack == "tamper":
                data["extra1"] += b" "
            if attack == "extra":
                data["malware"] = b"{}"
            if attack == "index":
                policy["index.json"] = "e"*64
            with self.subTest(attack=attack):
                self.deny(p1.verified_catalog, ib, data, policy, "c"*40)

    def test_source_pins_pg19_and_unsupported(self):
        r = record()
        self.assertEqual(p1.immutable_source(source(), 19, r)["commit"], "b"*40)
        self.deny(p1.immutable_source, source(), 18, r)
        self.deny(p1.immutable_source, source(), 19, record("attacker"))
        s = source()
        s["upstream"]["commit"] = None
        self.deny(p1.immutable_source, s, 19, r)

    def test_multi_pg_pin_never_inherits_aggregate_tag(self):
        r = record("pgaudit", "19")
        r["upstream"] = {"repository": "pgaudit/pgaudit",
                         "perPostgresql": {"19": {"version": "19.1", "ref": "19.1"}}}
        s = source("pgaudit")
        s["upstream"] = {"repository": "pgaudit/pgaudit",
                         "perPostgresql": {"19": {"version": "19.1",
                                                "ref": "19.1", "commit": "b"*40}}}
        self.assertEqual(p1.immutable_source(s, 19, r)["version"], "19.1")
        s["upstream"]["perPostgresql"]["19"]["ref"] = "18.1"
        self.deny(p1.immutable_source, s, 19, r)

    def test_release_id_and_substitution(self):
        r, release, _ = make_release()
        self.assertEqual(len(p1.release_assets(r, release, 4001, 7001)), 4)
        for field, bad in (("id", 3), ("tag_name", "v3-windows.2"),
                           ("draft", True), ("target_commitish", "main")):
            x = copy.deepcopy(release)
            x[field] = bad
            with self.subTest(field=field):
                self.deny(p1.release_assets, r, x, 4001, 7001)

    def test_release_asset_id_filename_digest_url_attacks(self):
        r, release, _ = make_release()
        for key, bad in (("id", 1), ("name", "../bad.zip"),
                         ("digest", "sha256:"+"0"*64),
                         ("browser_download_url", "https://evil.invalid/x")):
            x = copy.deepcopy(release)
            x["assets"][1][key] = bad
            with self.subTest(field=key):
                self.deny(p1.release_assets, r, x, 4001, 7001)

    def test_rehash_all_original_assets_and_checksums(self):
        r, release, assets = make_release()
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for name, blob in assets.items():
                (d/name).write_bytes(blob)
            amap = p1.release_assets(r, release, 4001, 7001)
            self.assertEqual(len(p1.rehash_release(d, amap, r)), 4)
            (d/r["postgresql"]["19"]["asset"]).write_bytes(b"tamper")
            self.deny(p1.rehash_release, d, amap, r)

    def test_rehash_rejects_replaced_checksum_and_extra_file(self):
        r, release, assets = make_release()
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for n, blob in assets.items():
                (d/n).write_bytes(blob)
            amap = p1.release_assets(r, release, 4001, 7001)
            (d/"SHA256SUMS.txt").write_bytes(b"a"*64+b"  bad.zip\n")
            self.deny(p1.rehash_release, d, amap, r)
            (d/"SHA256SUMS.txt").write_bytes(assets["SHA256SUMS.txt"])
            (d/"extra.zip").write_bytes(b"extra")
            self.deny(p1.rehash_release, d, amap, r)

    def test_checksum_duplicate_and_traversal(self):
        self.deny(p1.parse_sums, (b"a"*64+b"  zip.zip\n")*2)
        self.deny(p1.parse_sums, b"a"*64+b"  ../evil\n")
        self.deny(p1.parse_sums, b"\xff")

    def test_signed_run_attempt_identity(self):
        run = {"id": 567, "run_attempt": 2,
               "repository": {"id": 7001, "full_name": "pgextwin/example"},
               "head_sha": "a"*40, "head_branch": "main",
               "event": "workflow_dispatch", "path": ".github/workflows/promote.yml",
               "status": "completed", "conclusion": "success",
               "actor": {"login": "human"}}
        params = dict(repo="pgextwin/example",repo_id=7001,packaging_sha="a"*40,
                      run_id=567,attempt=2)
        p1.signed_run(run, **params)
        for key,bad in (("run_attempt",1), ("event","push"), ("conclusion","failure"),
                        ("head_sha","b"*40), ("path",".github/workflows/test.yml")):
            x = dict(run, **{key:bad})
            with self.subTest(key=key):
                self.deny(p1.signed_run, x, **params)

    def test_certificate_claims_policy_fixture_not_cryptographic(self):
        results, params = cert_fixture()
        p1.signed_certificate(results, **params)
        for key,bad in (("sourceRepositoryIdentifier","7002"),
                        ("runInvocationURI","https://github.com/pgextwin/example/actions/runs/567/attempts/2"),
                        ("buildSignerDigest","c"*40),
                        ("sourceRepositoryRef","refs/heads/feature"),
                        ("issuer","https://fake.invalid"),
                        ("sourceRepositoryDigest","b"*40)):
            rs = copy.deepcopy(results)
            rs[0]["verificationResult"]["signature"]["certificate"][key] = bad
            with self.subTest(key=key):
                self.deny(p1.signed_certificate, rs, **params)

    def test_wrong_predicate_subject_and_spdx(self):
        rs, params = cert_fixture()
        for attack in ("predicate","digest","sbom","timestamp"):
            x = copy.deepcopy(rs)
            v = x[0]["verificationResult"]
            if attack == "predicate": v["statement"]["predicateType"] = p1.PROVENANCE
            elif attack == "digest": v["statement"]["subject"][0]["digest"]["sha256"] = "0"*64
            elif attack == "sbom": v["statement"]["predicate"]["spdxVersion"] = "SPDX-2.2"
            else: v["verifiedTimestamps"] = []
            with self.subTest(attack=attack):
                self.deny(p1.signed_certificate, x, **params)

    def test_offline_missing_or_changed_root_stops_before_gh(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)/"trusted_root.jsonl"
            root.write_text("untrusted")
            z = Path(d)/"test.zip"
            z.write_bytes(b"zip")
            with patch.object(p1.subprocess, "run") as run:
                self.deny(p1.verify_sigstore_offline, z, {},
                          repo="pgextwin/example", repo_id=7001,
                          packaging_sha="a"*40, signer_sha="b"*40,
                          run_id=567, attempt=1, root_path=root,
                          root_sha="0"*64, bundles={})
                run.assert_not_called()

    def test_sigstore_requires_both_real_bundles(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            root = base/"root.jsonl"; root.write_bytes(b"trusted")
            zip_path = base/"example.zip"; zip_path.write_bytes(b"zip")
            with patch.object(p1.subprocess, "run") as called:
                self.deny(p1.verify_sigstore_offline, zip_path, {},
                    repo="pgextwin/example", repo_id=7001, packaging_sha="a"*40,
                    signer_sha="b"*40, run_id=567, attempt=1,
                    root_path=root, root_sha=p1.sha(root), bundles={})
                called.assert_not_called()

    def test_fleet_partial_fail_closed_historical(self):
        records = {"name": {"postgresql": {"14": {"available": True},
                                          "19": {"available": False}}},
                   "next": {"postgresql": {"15": {"available": True}}}}
        tally = p1.fleet_counts(records, {
            ("name","14"): {"integrityVerified": True,
                            "signatureVerified": False, "reason":"missing bundle"}})
        self.assertEqual(tally["expected"], 2)
        self.assertEqual(tally["integrityVerified"], 1)
        self.assertEqual(tally["signatureVerified"], 0)
        self.assertEqual(tally["blocked"], 1)
        self.assertEqual(tally["unverified"], 1)
        self.assertFalse(tally["complete"])
        self.assertFalse(tally["publicationAuthorized"])


if __name__ == "__main__":
    unittest.main()
