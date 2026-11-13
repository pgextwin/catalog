"""Offline exact-name and trust-boundary tests for OSGeo installer source listings."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from discover_osgeo_windows_bundles import parse_listing
import issue112_osgeo_installer_source_gap as gap


LISTED = {
    "14": ["postgis-bundle-pg14x64-3.2.2-installer-src.zip",
           "postgis-bundle-pg14x64-3.3.2-installer-src.zip",
           "postgis-bundle-pg14x64-3.5.0-installer-src.zip"],
    "15": ["postgis-bundle-pg15x64-3.3.2-installer-src.zip",
           "postgis-bundle-pg15x64-3.5.0-installer-src.zip"],
    "16": ["postgis-bundle-pg16x64-3.5.0-installer-src.zip"],
    "17": ["postgis-bundle-pg17x64-3.5.0-installer-src.zip"],
    "18": ["postgis-bundle-pg18x64-3.6.1-installer-src.zip"],
}


class SourceIndexGapTests(unittest.TestCase):
    def test_observed_official_index_names_do_not_match_shipped_versions(self):
        report = gap.audit(copy.deepcopy(LISTED))
        self.assertEqual(len(report["rows"]), 5)
        self.assertFalse(report["sourceToBinaryProvenanceVerified"])
        self.assertFalse(report["publicGetAuthorized"])
        for row in report["rows"]:
            self.assertFalse(row["matchingInstallerSourceFilenameListed"])
            self.assertEqual(row["status"], "NO_MATCHING_INSTALLER_SOURCE_FILENAME_LISTED")
            self.assertFalse(row["installerSourceIsCompleteBinaryBuildInput"])
            self.assertFalse(row["producerToOriginalZipAttestationVerified"])
            for gate in ("publicGetAuthorized", "mirrorAuthorized", "publisherAuthorized",
                         "releaseAuthorized", "componentLicenseNoticeClosureVerified"):
                self.assertFalse(row[gate])

    def test_name_match_is_not_promoted_to_provenance_or_public_get(self):
        data = copy.deepcopy(LISTED)
        data["17"].append("postgis-bundle-pg17x64-3.6.2-installer-src.zip")
        row = gap.audit(data)["rows"][3]
        self.assertTrue(row["matchingInstallerSourceFilenameListed"])
        self.assertEqual(row["status"], "NAME_MATCH_ONLY_NOT_PROVENANCE")
        self.assertFalse(row["producerToOriginalZipAttestationVerified"])
        self.assertFalse(row["publicGetAuthorized"])

    def test_new_pg18_exact_installer_source_name_is_not_producer_proof(self):
        # OSUOSL public mirror listed this name on 2026-11-13; unlike the
        # 2026-11-11 historical fixture, the PG18 version now name-matches.
        # Directory names cannot prove actual source-to-binary provenance.
        current = copy.deepcopy(LISTED)
        current["18"].append("postgis-bundle-pg18x64-3.7.0-installer-src.zip")
        report = gap.audit(current)
        row = report["rows"][4]
        self.assertEqual(row["listedInstallerSourceVersions"], ["3.6.1", "3.7.0"])
        self.assertTrue(row["matchingInstallerSourceFilenameListed"])
        self.assertEqual(row["status"], "NAME_MATCH_ONLY_NOT_PROVENANCE")
        self.assertFalse(report["sourceToBinaryProvenanceVerified"])
        for flag in ("installerSourceIsCompleteBinaryBuildInput",
                     "producerToOriginalZipAttestationVerified",
                     "componentLicenseNoticeClosureVerified",
                     "publicGetAuthorized", "mirrorAuthorized",
                     "releaseAuthorized", "publisherAuthorized"):
            self.assertIs(row[flag], False)

    def test_source_filename_requires_exact_version_major_and_type(self):
        data = copy.deepcopy(LISTED)
        data["18"] += ["postgis-bundle-pg18-3.7.0x64.zip",
                       "postgis-bundle-pg18x64-3.7.0-installer-src.zip.md5",
                       "postgis-bundle-pg18x64-3.7.0-installer-src.exe",
                       "postgis-bundle-pg18x64-3.7.0-installer-src.zip?x=1"]
        self.assertFalse(gap.audit(data)["rows"][4]["matchingInstallerSourceFilenameListed"])
        data["18"].append("postgis-bundle-pg14x64-3.7.0-installer-src.zip")
        with self.assertRaisesRegex(ValueError, "Cross-major"):
            gap.audit(data)

    def test_invalid_or_partial_indexes_denied(self):
        for bad in ({}, {"14": []}, {**LISTED, "19": []}):
            with self.assertRaises(ValueError):
                gap.audit(bad)
        data = copy.deepcopy(LISTED)
        data["14"].append(data["14"][0])
        with self.assertRaises(ValueError):
            gap.audit(data)
        for pg in ("13", "19", "18/../../"):
            with self.assertRaises(ValueError):
                gap.read_index(pg)

    def test_untrusted_listing_cannot_supply_other_origin_or_filename(self):
        names = parse_listing('''<a href="../">parent</a>
            <a href="postgis-bundle-pg18x64-3.6.1-installer-src.zip">safe</a>
            <a href="https://evil.invalid/postgis-bundle-pg18x64-3.7.0-installer-src.zip">evil</a>
            <a href="../postgis-bundle-pg18x64-3.7.0-installer-src.zip">evil</a>
            <a href="postgis-bundle-pg18x64-3.7.0-installer-src.zip?token=evil">evil</a>
        ''')
        self.assertEqual(names, LISTED["18"])


if __name__ == "__main__":
    unittest.main()
