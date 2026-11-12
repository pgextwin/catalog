"""Offline hostile metadata/signature intake tests; no provider downloads."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgroonga_detached_signature_review as review


def fixtures():
    records, assets = [], []
    for pg, (sid, size, sha) in review.SIDECARS.items():
        zname = f"pgroonga-4.1.0-postgresql-{pg}-x64.zip"
        zid, zbytes, zsha = 600000000 + int(pg), 53_000_000 + int(pg), "a" * 64
        records.append({"pgMajor": pg, "assetId": zid, "assetName": zname,
                        "originalBytes": zbytes, "originalSha256": zsha})
        for name, ident, signer in ((zname, (zid, zbytes, zsha), "github-actions[bot]"),
                                    (zname + ".asc", (sid, size, sha), "groonga-release")):
            assets.append({"name": name, "id": ident[0], "size": ident[1],
                           "digest": "sha256:" + ident[2], "state": "uploaded",
                           "browser_download_url": review.URL + name,
                           "uploader": {"login": signer}})
    baseline = {"schemaVersion": "pgextwin-issue112-pgroonga-official-release-watch-baseline/v1",
                "trust": "UNVERIFIED_METADATA_NEVER_AUTHORIZE", "sourceRepo": review.REPO,
                "releaseTag": review.VERSION, "releaseId": review.RELEASE_ID,
                "downloadAuthorized": False, "publicationAuthorized": False,
                "redistributionAuthorized": False, "records": records}
    release = {"id": review.RELEASE_ID, "tag_name": review.VERSION,
               "draft": False, "prerelease": False, "assets": assets}
    return baseline, release


class Review(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.file = Path(self.temp.name) / "baseline.json"
        self.baseline, self.release = fixtures()
        self.save()

    def save(self):
        self.file.write_text(json.dumps(self.baseline), encoding="utf-8")

    def test_valid_remains_denied(self):
        result = review.audit(self.file, self.release, lambda pg: "A" * 16)
        self.assertEqual(len(result["signaturePairs"]), 5)
        for key, value in review.DENIED.items():
            self.assertIs(result[key], False)
        self.assertTrue(all(r["signaturePacketsOnlyNotVerified"] for r in result["signaturePairs"]))

    def test_hostile_release_assets(self):
        changes = (
            lambda x: x.update(tag_name="4.0.9"),
            lambda x: x.update(draft=True),
            lambda x: x["assets"].append(copy.deepcopy(x["assets"][0])),
            lambda x: x["assets"][1].update(size=832),
            lambda x: x["assets"][1].update(digest="sha256:" + "f" * 64),
            lambda x: x["assets"][1].update(id=0),
            lambda x: x["assets"][1]["uploader"].update(login="attacker"),
            lambda x: x["assets"][1].update(browser_download_url="https://evil.test/x.asc"),
            lambda x: x["assets"][0].update(size=1),
            lambda x: x["assets"][0].update(state="deleted"),
        )
        for mutate in changes:
            with self.subTest(mutate=changes.index(mutate)):
                data = copy.deepcopy(self.release)
                mutate(data)
                with self.assertRaises(ValueError):
                    review.validate_metadata(data, review.strict_baseline(self.file))

    def test_hostile_baselines(self):
        for mutate in (
            lambda x: x.update(downloadAuthorized=True),
            lambda x: x.update(releaseId=0),
            lambda x: x["records"].pop(),
            lambda x: x["records"].append(copy.deepcopy(x["records"][0])),
        ):
            data = copy.deepcopy(self.baseline)
            mutate(data)
            self.file.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                review.strict_baseline(self.file)
        self.file.write_text('{"x":1,"x":2}', encoding="utf-8")
        with self.assertRaises(ValueError):
            review.strict_baseline(self.file)

    def test_bad_armored_bytes_deny(self):
        with self.assertRaises(ValueError):
            review.inspect_armored_signature("19", lambda: b"")
        with self.assertRaises(ValueError):
            review.inspect_armored_signature("18", lambda: b"forged signature")


if __name__ == "__main__":
    unittest.main()
