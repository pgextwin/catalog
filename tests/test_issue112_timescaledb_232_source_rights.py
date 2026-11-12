"""Offline hostile regression: current source rights do not authorize any delivery."""
import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_timescaledb_232_source_rights as probe

class RightsContinuity(unittest.TestCase):
    def setUp(self):
        self.texts = {
            "LICENSE": 'Outside of the "tsl" directory; Within the "tsl" folder; separate shared object files',
            "LICENSE-APACHE": "Apache License Version 2.0",
            "NOTICE": "TimescaleDB (TM) LICENSE-APACHE LICENSE-TIMESCALE",
            "tsl/LICENSE-TIMESCALE": "TIMESCALE LICENSE AGREEMENT 2.1 2.2",
            probe.WORKFLOW: probe.DELEGATED + " upload-artifacts: true publish_release",
        }
        self.pins = {path: probe.blob_sha(content.encode()) for path, content in self.texts.items()}
        self.ref = {"ref": "refs/tags/2.32.0",
                    "object": {"type": "commit", "sha": probe.COMMIT,
                               "url": probe.API + "/git/commits/" + probe.COMMIT}}

    def provider(self, changed=None):
        changed = changed or {}
        def get(url):
            if url.endswith("/git/ref/tags/" + probe.TAG):
                return copy.deepcopy(changed.get("ref", self.ref))
            prefix = probe.API + "/contents/"
            if not url.startswith(prefix) or not url.endswith("?ref=" + probe.COMMIT):
                raise ValueError("Unexpected outbound source read")
            path = url[len(prefix):-len("?ref=" + probe.COMMIT)]
            content = changed.get("text:" + path, self.texts[path]).encode()
            return {"path": path,
                    "sha": changed.get("sha:" + path, self.pins[path]),
                    "encoding": "base64", "content": base64.b64encode(content).decode()}
        return get

    def test_latest_originals_historical_rights_and_source_docs_join_without_public_permission(self):
        report = probe.audit(get_json=self.provider(), test_pins=self.pins)
        self.assertTrue(report["rightsDocumentsSameBlobsAs231"])
        self.assertEqual(report["originalZipMajorsIndependentlyPinned"], ["16", "17", "18"])
        self.assertEqual(report["tag"], "2.32.0")
        for key, value in report.items():
            if key.endswith(("Authorized", "Verified", "Closed", "Pinned")) and type(value) is bool:
                self.assertFalse(value, key)
        self.assertIn("@main", report["delegatedWindowsWorkflow"])

    def test_wrong_tag_or_commit_is_denied(self):
        for object_change in ({"ref": "refs/tags/2.31.0"},
                              {"object": {"type": "commit", "sha": "0"*40,
                                          "url": probe.API + "/git/commits/" + probe.COMMIT}}):
            ref = copy.deepcopy(self.ref)
            ref.update(object_change)
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                probe.audit(get_json=self.provider({"ref": ref}), test_pins=self.pins)

    def test_source_content_or_blob_identity_cannot_drift(self):
        path = "NOTICE"
        for change in ({"text:" + path: "forged replacement"},
                       {"sha:" + path: "0"*40}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                probe.audit(get_json=self.provider(change), test_pins=self.pins)
        with self.assertRaises(ValueError):
            probe.audit(get_json=self.provider(), test_pins={path: "0"*40})

    def test_mutated_unselected_latest_original_and_old_rights_also_deny(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "external").mkdir()
            names = [probe.HISTORICAL, probe.HISTORICAL_RIGHTS, probe.LATEST,
                     "external/timescaledb-232-original-evidence-v1.json"]
            for rel in names:
                (root / rel).write_text((probe.ROOT / rel).read_text())
            target = root / "external/timescaledb-232-original-evidence-v1.json"
            doc = json.loads(target.read_text())
            doc["assets"][2]["originalBytes"] += 1
            target.write_text(json.dumps(doc))
            with self.assertRaises(ValueError):
                probe.audit(root=root, get_json=self.provider(), test_pins=self.pins)
            target.write_text((probe.ROOT / names[-1]).read_text())
            rights = root / probe.HISTORICAL_RIGHTS
            older = json.loads(rights.read_text())
            older["permissions"]["publicGet"] = True
            rights.write_text(json.dumps(older))
            with self.assertRaises(ValueError):
                probe.audit(root=root, get_json=self.provider(), test_pins=self.pins)

    def test_fixed_only_api_host_and_no_redirect(self):
        with self.assertRaises(ValueError):
            probe.github_json("https://malicious.example/contents/LICENSE")
        with self.assertRaises(ValueError):
            probe.NoRedirect().redirect_request(None, None, None, None, None)

if __name__ == "__main__":
    unittest.main()
