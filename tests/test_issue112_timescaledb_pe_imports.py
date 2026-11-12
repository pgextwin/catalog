"""Hostile offline TimescaleDB import-graph tests; no download or publication."""
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
import issue112_timescaledb_pe_imports as audit


def fixture_zip(rows=None):
    if rows is None:
        rows = [
            ("timescaledb/timescaledb-2.31.0.dll",
             fake_pe(b"timescaledb-tsl-2.31.0.dll", b"ucrtbase.dll")),
            ("timescaledb/timescaledb-tsl-2.31.0.dll",
             fake_pe(b"postgres.exe", b"timescaledb.dll")),
            ("timescaledb/timescaledb.dll",
             fake_pe(b"kernel32.dll", b"unknown.dll")),
        ]
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for path, body in rows:
            archive.writestr(path, body)
    return out.getvalue()


class Response(io.BytesIO):
    def geturl(self):
        return "https://release-assets.githubusercontent.com/fixture"


class Opener:
    def __init__(self, data):
        self.data = data

    def open(self, request, timeout=None):
        return Response(self.data)


class OriginalPeDependencyTests(unittest.TestCase):
    def test_exact_imports_and_unbundled_references_are_non_authorizing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "original.zip"
            path.write_bytes(fixture_zip())
            report = audit.inspect_imports(path)
        self.assertTrue(report["allImportTablesParsed"])
        self.assertEqual(len(report["dllImportReceipts"]), 3)
        first = report["dllImportReceipts"][0]
        self.assertEqual(first["bundledNameImports"],
                         ["timescaledb-tsl-2.31.0.dll"])
        self.assertEqual(first["nonbundledNameImports"], ["ucrtbase.dll"])
        names = {x["name"]: x for x in report["unbundledImportTriage"]}
        self.assertEqual(names["postgres.exe"]["category"],
                         "POSTGRES_HOST_NAME_HINT_ONLY")
        self.assertEqual(names["kernel32.dll"]["category"],
                         "WINDOWS_OS_NAME_HINT_ONLY")
        self.assertEqual(names["unknown.dll"]["category"],
                         "NONBUNDLED_IMPORT_PROVIDER_UNVERIFIED")
        self.assertEqual(names["unknown.dll"]["referencedBy"],
                         ["timescaledb/timescaledb.dll"])
        for row in report["dllImportReceipts"]:
            self.assertFalse(row["actualWindowsLoaderResolutionVerified"])
            self.assertFalse(row["dynamicLoadLibraryCoverageVerified"])
            self.assertFalse(row["componentLicenseNoticeVerified"])

    def test_header_only_pe_is_reported_as_not_parsed(self):
        # The earlier member receipt checks only PE headers, not import tables.
        from test_issue112_timescaledb_dll_receipts import pe_bytes
        good = [
            ("timescaledb/timescaledb-2.31.0.dll", pe_bytes()),
            ("timescaledb/timescaledb-tsl-2.31.0.dll",
             fake_pe(b"postgres.exe")),
            ("timescaledb/timescaledb.dll", fake_pe(b"kernel32.dll")),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "header-only.zip"
            path.write_bytes(fixture_zip(good))
            result = audit.inspect_imports(path)
        self.assertFalse(result["allImportTablesParsed"])
        self.assertEqual(result["dllImportReceipts"][0]["analysis"], "NOT_PARSED")

    def test_archive_guard_rejects_bad_paths_wrong_count_and_identity(self):
        bad = (
            [("../outside.dll", fake_pe())] +
            [("timescaledb/timescaledb-tsl-2.31.0.dll", fake_pe()),
             ("timescaledb/timescaledb.dll", fake_pe())],
            [("timescaledb/timescaledb-2.31.0.dll", fake_pe()),
             ("timescaledb/timescaledb-tsl-2.31.0.dll", fake_pe())],
            [("timescaledb/renamed.dll", fake_pe()),
             ("timescaledb/timescaledb-tsl-2.31.0.dll", fake_pe()),
             ("timescaledb/timescaledb.dll", fake_pe())],
        )
        with tempfile.TemporaryDirectory() as tmp:
            for i, rows in enumerate(bad):
                path = Path(tmp) / f"bad-{i}.zip"
                path.write_bytes(fixture_zip(rows))
                with self.subTest(i=i), self.assertRaises(ValueError):
                    audit.inspect_imports(path)

    def test_only_exact_pinned_original_bytes_are_audited(self):
        data = fixture_zip()
        pin = {"name": "original.zip", "url": "https://github.com/test/a.zip",
               "assetId": 5, "size": len(data),
               "sha256": hashlib.sha256(data).hexdigest()}
        with mock.patch.object(audit, "original_pin", return_value=pin):
            with self.assertRaises(ValueError):
                audit.audit("18", opener=Opener(data + b"unexpected"))
            with self.assertRaises(ValueError):
                audit.audit("18", opener=Opener(data[:-3]))
            result = audit.audit("18", opener=Opener(data))
        self.assertEqual(result["originalSha256"], pin["sha256"])
        self.assertEqual(result["state"], "CANDIDATE_ONLY_NONPUBLISHING")
        for field in (
            "effectiveWindowsLoaderResolutionVerified",
            "dynamicDependenciesVerified", "exactComponentLicenseAndNoticesVerified",
            "producerRunBoundToAssetDigestVerified",
            "newSourceSpecificSignedAdmission", "publicGetAuthorized",
            "mirrorAuthorized", "releaseAuthorized", "publisherAuthorized",
        ):
            self.assertIs(result[field], False)


if __name__ == "__main__":
    unittest.main()
