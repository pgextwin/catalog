"""No-network hostile tests for an exact canonical original version.txt receipt."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_osgeo_winnie_live_original as live


class ExactOriginalReceiptTests(unittest.TestCase):
    def record(self, pg="18"):
        _, size, sha = live.ORIGINALS[pg]
        report = {"status": "CANDIDATE_ONLY", "originalZipBytes": size,
                  "originalZipSha256": sha, "versionTxtFound": False}
        report.update({field: False for field in live.DENIALS})
        return report

    def test_all_majors_have_only_canonical_origins_and_no_admission(self):
        for pg in sorted(live.ORIGINALS):
            version, size, sha = live.ORIGINALS[pg]
            with self.subTest(pg=pg), mock.patch.object(live, "read_original", return_value=(size, sha)) as get, \
                    mock.patch.object(live, "audit", return_value=self.record(pg)) as audit, \
                    mock.patch.object(live, "metadata_lines", return_value=([], None, None)):
                receipt = live.review_original(pg, opener=object())
                url = get.call_args.args[0]
                self.assertEqual(url, f"https://download-cache.osgeo.org/postgis/windows/pg{pg}/postgis-bundle-pg{pg}-{version}x64.zip")
                self.assertFalse(receipt["originRedirectAllowed"])
                self.assertEqual(receipt["sourceOriginalUrl"], url)
                self.assertTrue(all(receipt[key] is False for key in live.DENIALS))
                self.assertEqual(audit.call_args.args[1], pg)

    def test_unpinned_major_never_touches_network(self):
        with mock.patch.object(live, "read_original") as get:
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                live.review_original("19")
            get.assert_not_called()

    def test_wrong_source_byte_size_or_hash_fails_before_inspection(self):
        _, size, sha = live.ORIGINALS["18"]
        for result in ((size - 1, sha), (size, "0" * 64)):
            with self.subTest(result=result), mock.patch.object(live, "read_original", return_value=result), \
                    mock.patch.object(live, "audit") as audit, \
                    mock.patch.object(live, "metadata_lines", return_value=([], None, None)):
                with self.assertRaisesRegex(ValueError, "SHA256/size mismatch"):
                    live.review_original("18", opener=object())
                audit.assert_not_called()

    def test_spoofed_positive_gate_is_rejected(self):
        _, size, sha = live.ORIGINALS["18"]
        for field in live.DENIALS:
            report = self.record()
            report[field] = True
            with self.subTest(field=field), mock.patch.object(live, "read_original", return_value=(size, sha)), \
                    mock.patch.object(live, "audit", return_value=report), \
                    mock.patch.object(live, "metadata_lines", return_value=([], None, None)):
                with self.assertRaisesRegex(ValueError, "deny gate"):
                    live.review_original("18", opener=object())

    def test_missing_denial_flag_and_status_injection_rejected(self):
        _, size, sha = live.ORIGINALS["18"]
        for mutation in (lambda d: d.pop("mirrorAuthorized"),
                         lambda d: d.update(status="PUBLIC_COMPLETE"),
                         lambda d: d.update(originalZipSha256="0" * 64)):
            report = self.record()
            mutation(report)
            with mock.patch.object(live, "read_original", return_value=(size, sha)), \
                    mock.patch.object(live, "audit", return_value=report), \
                    mock.patch.object(live, "metadata_lines", return_value=([], None, None)):
                with self.assertRaisesRegex(ValueError, "deny gate"):
                    live.review_original("18", opener=object())

    def test_default_transport_installs_no_redirect_handler(self):
        _, size, sha = live.ORIGINALS["18"]
        with mock.patch.object(live.urllib.request, "build_opener", return_value=object()) as build, \
                mock.patch.object(live, "read_original", return_value=(size, sha)), \
                mock.patch.object(live, "audit", return_value=self.record()), \
                mock.patch.object(live, "metadata_lines", return_value=([], None, None)):
            live.review_original("18")
            self.assertIsInstance(build.call_args.args[0], live.NoRedirect)

    def test_duplicate_component_metadata_remains_unparsed_and_denied(self):
        _, size, sha = live.ORIGINALS["15"]
        with mock.patch.object(live, "read_original", return_value=(size, sha)), \
                mock.patch.object(live, "audit", side_effect=ValueError("Conflicting or duplicate Winnie component version")), \
                mock.patch.object(live, "metadata_lines",
                                  return_value=(["GEOS VERSION: 3.1.0", "GEOS VERSION: 3.2.0"], 40, "f" * 64)):
            receipt = live.review_original("15", opener=object())
        self.assertFalse(receipt["componentClaimsParsed"])
        self.assertEqual(receipt["packagingComponentVersionClaims"], {})
        self.assertEqual(receipt["manifestObservation"], "DUPLICATE_COMPONENT_LABELS_UNPARSED")
        self.assertEqual(receipt["versionTxtSha256"], "f" * 64)
        self.assertTrue(all(receipt[field] is False for field in live.DENIALS))

    def test_other_manifest_errors_are_not_suppressed(self):
        _, size, sha = live.ORIGINALS["18"]
        with mock.patch.object(live, "read_original", return_value=(size, sha)), \
                mock.patch.object(live, "audit", side_effect=ValueError("CRC mismatch")), \
                mock.patch.object(live, "metadata_lines") as lines:
            with self.assertRaisesRegex(ValueError, "CRC mismatch"):
                live.review_original("18", opener=object())
            lines.assert_not_called()

    def test_real_bounded_raw_member_observation_preserves_digest(self):
        content = b"GEOS VERSION: 3.1.0\nGEOS VERSION: 3.2.0\n"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.zip"
            member = "postgis-bundle-pg18-3.7.0x64/version.txt"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr(member, content)
            lines, size, sha = live.metadata_lines(path, "18")
        self.assertEqual(lines, ["GEOS VERSION: 3.1.0", "GEOS VERSION: 3.2.0"])
        self.assertEqual(size, len(content))
        self.assertEqual(sha, hashlib.sha256(content).hexdigest())


if __name__ == "__main__":
    unittest.main()
