"""Hostile tests: exact 2.32.0 PE imports are an observation, not GET approval."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
from test_issue112_osgeo_dependency_inventory import fake_pe
from test_issue112_timescaledb_dll_receipts import pe_bytes
import issue112_timescaledb_pe_imports as audit


def fixture_zip(version="2.32.0", rows=None):
    if rows is None:
        rows = [
            (f"timescaledb/timescaledb-{version}.dll",
             fake_pe(f"timescaledb-tsl-{version}.dll".encode(), b"ucrtbase.dll")),
            (f"timescaledb/timescaledb-tsl-{version}.dll",
             fake_pe(b"postgres.exe", b"timescaledb.dll")),
            ("timescaledb/timescaledb.dll",
             fake_pe(b"kernel32.dll", b"missing-provider.dll")),
        ]
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for path, content in rows:
            z.writestr(path, content)
    return out.getvalue()


class Response(io.BytesIO):
    def geturl(self):
        return "https://release-assets.githubusercontent.com/fixture-232"


class Opener:
    def __init__(self, data):
        self.data = data

    def open(self, request, timeout=None):
        return Response(self.data)


class LatestPeImportsTests(unittest.TestCase):
    def test_232_pins_match_all_three_original_exact_asset_receipts(self):
        expected = {
            "16": (739177731, 9637877,
                   "69124f50da0206e6fa92bae9918f200875a406977cb18fd9e92187d4910f179a"),
            "17": (739179170, 9638195,
                   "773596b56f53ac97595b8c36e09ae7f1125bdbc28f6aaa3efa0c8d92bf129c17"),
            "18": (739179122, 9639648,
                   "309eba6bb24c3562b9ecfd279ff1bbe0eb638eaed8b16395c839047c670a9c45"),
        }
        for pg, (asset, size, digest) in expected.items():
            with self.subTest(pg=pg):
                pin = audit.latest_original_pin(pg)
                self.assertEqual((pin["assetId"], pin["size"], pin["sha256"]),
                                 (asset, size, digest))
                self.assertEqual(pin["releaseId"], 442824242)
        for invalid in ("14", "15", "19", "../16", ""):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                audit.latest_original_pin(invalid)

    def test_mismatched_independent_receipt_is_denied(self):
        original = audit.latest_original_pin("16")
        mismatches = (
            {"assetId": 739179170},
            {"originalBytes": original["size"] - 1},
            {"originalSha256": "0" * 64},
            {"assetName": "timescaledb-postgresql-17-windows-amd64.zip"},
        )
        row = {"assetId": original["assetId"],
               "originalBytes": original["size"],
               "originalSha256": original["sha256"],
               "assetName": original["name"]}
        for delta in mismatches:
            with self.subTest(delta=delta), mock.patch.object(
                    audit, "verified_assets",
                    return_value={"16": {**row, **delta}}):
                with self.assertRaises(ValueError):
                    audit.latest_original_pin("16")

    def test_new_import_basename_resolution_is_not_dependency_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "original.zip"
            path.write_bytes(fixture_zip())
            report = audit.inspect_imports(path, version="2.32.0")
        self.assertTrue(report["allImportTablesParsed"])
        self.assertEqual(len(report["dllImportReceipts"]), 3)
        self.assertEqual(report["dllImportReceipts"][0]["bundledNameImports"],
                         ["timescaledb-tsl-2.32.0.dll"])
        triage = {x["name"]: x for x in report["unbundledImportTriage"]}
        self.assertEqual(triage["postgres.exe"]["category"],
                         "POSTGRES_HOST_NAME_HINT_ONLY")
        self.assertEqual(triage["kernel32.dll"]["category"],
                         "WINDOWS_OS_NAME_HINT_ONLY")
        self.assertEqual(triage["missing-provider.dll"]["category"],
                         "NONBUNDLED_IMPORT_PROVIDER_UNVERIFIED")
        self.assertFalse(triage["missing-provider.dll"]["resolvedOnExactTargetWindows"])
        for member in report["dllImportReceipts"]:
            self.assertFalse(member["actualWindowsLoaderResolutionVerified"])
            self.assertFalse(member["componentLicenseNoticeVerified"])
            self.assertFalse(member["producerSourceToBinaryProvenanceVerified"])

    def test_231_dll_names_cannot_pass_as_232(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "old.zip"
            path.write_bytes(fixture_zip(version="2.31.0"))
            with self.assertRaises(ValueError):
                audit.inspect_imports(path, version="2.32.0")
            self.assertTrue(audit.inspect_imports(path, version="2.31.0")
                            ["allImportTablesParsed"])
            with self.assertRaises(ValueError):
                audit.inspect_imports(path, version="2.33.0")

    def test_bad_zip_names_and_unparsed_pe_do_not_get_accepted(self):
        rows = [
            ("timescaledb/timescaledb-2.32.0.dll", pe_bytes()),
            ("timescaledb/timescaledb-tsl-2.32.0.dll", fake_pe(b"postgres.exe")),
            ("timescaledb/timescaledb.dll", fake_pe(b"kernel32.dll")),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.zip"
            path.write_bytes(fixture_zip(rows=rows))
            report = audit.inspect_imports(path, version="2.32.0")
            self.assertFalse(report["allImportTablesParsed"])
            self.assertEqual(report["dllImportReceipts"][0]["analysis"], "NOT_PARSED")
            for malformed in (
                rows[:2],
                [("../escape.dll", fake_pe())] + rows[1:],
                [(rows[0][0], rows[0][1]), (rows[0][0].upper(), rows[1][1]),
                 rows[2]],
            ):
                path.write_bytes(fixture_zip(rows=malformed))
                with self.assertRaises(ValueError):
                    audit.inspect_imports(path, version="2.32.0")

    def test_exact_full_zip_digest_required_and_no_authority_on_success(self):
        data = fixture_zip()
        pin = {"name": "original.zip",
               "url": "https://github.com/timescale/timescaledb/releases/download/2.32.0/original.zip",
               "assetId": 739179122, "size": len(data),
               "sha256": hashlib.sha256(data).hexdigest()}
        with mock.patch.object(audit, "latest_original_pin", return_value=pin):
            with self.assertRaises(ValueError):
                audit.audit("18", opener=Opener(data[:-1]), version="2.32.0")
            with self.assertRaises(ValueError):
                audit.audit("18", opener=Opener(data + b"extra"), version="2.32.0")
            verified = audit.audit("18", opener=Opener(data), version="2.32.0")
        self.assertEqual(verified["releaseTag"], "2.32.0")
        self.assertEqual(verified["originalSha256"], pin["sha256"])
        for field in ("effectiveWindowsLoaderResolutionVerified",
                      "dynamicDependenciesVerified",
                      "exactComponentLicenseAndNoticesVerified",
                      "producerRunBoundToAssetDigestVerified",
                      "newSourceSpecificSignedAdmission", "publicGetAuthorized",
                      "mirrorAuthorized", "releaseAuthorized",
                      "publisherAuthorized"):
            self.assertIs(verified[field], False, field)


if __name__ == "__main__":
    unittest.main()
