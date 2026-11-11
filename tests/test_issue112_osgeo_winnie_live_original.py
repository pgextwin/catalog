"""No-network hostile tests for an exact canonical original version.txt receipt."""
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_osgeo_winnie_live_original as live


class ExactOriginalReceiptTests(unittest.TestCase):
    def record(self, pg="18"):
        version, size, sha = live.ORIGINALS[pg]
        report = {"status": "CANDIDATE_ONLY", "originalZipBytes": size,
                  "originalZipSha256": sha, "versionTxtFound": False}
        report.update({field: False for field in live.DENIALS})
        return report

    def test_all_majors_have_only_canonical_origins_and_no_admission(self):
        for pg in sorted(live.ORIGINALS):
            version, size, sha = live.ORIGINALS[pg]
            with self.subTest(pg=pg), mock.patch.object(live, "read_original", return_value=(size, sha)) as get, \
                    mock.patch.object(live, "audit", return_value=self.record(pg)) as audit:
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
                    mock.patch.object(live, "audit") as audit:
                with self.assertRaisesRegex(ValueError, "SHA256/size mismatch"):
                    live.review_original("18", opener=object())
                audit.assert_not_called()

    def test_spoofed_positive_gate_is_rejected(self):
        _, size, sha = live.ORIGINALS["18"]
        for field in live.DENIALS:
            report = self.record()
            report[field] = True
            with self.subTest(field=field), mock.patch.object(live, "read_original", return_value=(size, sha)), \
                    mock.patch.object(live, "audit", return_value=report):
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
                    mock.patch.object(live, "audit", return_value=report):
                with self.assertRaisesRegex(ValueError, "deny gate"):
                    live.review_original("18", opener=object())

    def test_default_transport_installs_no_redirect_handler(self):
        _, size, sha = live.ORIGINALS["18"]
        with mock.patch.object(live.urllib.request, "build_opener", return_value=object()) as build, \
                mock.patch.object(live, "read_original", return_value=(size, sha)), \
                mock.patch.object(live, "audit", return_value=self.record()):
            live.review_original("18")
            self.assertIsInstance(build.call_args.args[0], live.NoRedirect)


if __name__ == "__main__":
    unittest.main()
