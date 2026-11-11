"""Offline hostile tests; rights receipts are never public-download admission."""
from pathlib import Path
import hashlib
import sys
import tempfile
import unittest
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import issue112_pgroonga_rights_audit as audit

def make(path, *, extra=None, remove=()):
    members = {
        "lib/pgroonga.dll": b"MZ:pgroonga",
        "bin/libgroonga.dll": b"MZ:groonga",
        "share/extension/pgroonga.control": b"default_version=4.1.0",
        "COPYING": b"PostgreSQL license",
        "share/LICENSE.txt": b"LGPL-2.1",
    }
    members.update(extra or {})
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            if name not in remove:
                z.writestr(name, data)

class ReceiptTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "original.zip"

    def report(self):
        return audit.audit_members(self.path, 18, require_pin=False)

    def test_never_authorizes_and_hashes_individual_binaries(self):
        make(self.path)
        result = self.report()
        self.assertEqual(result["binaryMemberCount"], 2)
        self.assertEqual(result["licenseNoticeCandidatesCount"], 2)
        for key in ("licenseNoticeClosureVerified", "thirdPartyComponentVersionsVerified",
                    "exactSourceToReleaseBinaryAttestationVerified",
                    "targetWindowsDynamicDependenciesVerified", "redistributionAuthorized",
                    "independentSigstoreAdmissionVerified", "publicGetAuthorized",
                    "mirrorAuthorized", "publisherAuthorized"):
            self.assertIs(result[key], False, key)
        row = next(x for x in result["binaryMemberReceipts"] if x["path"] == "bin/libgroonga.dll")
        self.assertEqual(row["sha256"], hashlib.sha256(b"MZ:groonga").hexdigest())
        self.assertFalse(row["componentLicenseNoticeVerified"])

    def test_similarly_named_binary_does_not_inherit_license(self):
        make(self.path, extra={"bin/copyright-vendor.dll": b"MZ:other"})
        result = self.report()
        self.assertEqual(result["licenseNoticeCandidatesCount"], 2)
        row = next(x for x in result["binaryMemberReceipts"]
                   if x["path"].endswith("copyright-vendor.dll"))
        self.assertFalse(row["exactProducerProvenanceVerified"])

    def test_referenced_license_bodies_are_inventoried_without_electing_terms(self):
        paths = ("share/groonga/mecab/BSD", "share/groonga/mecab/GPL",
                 "share/groonga/mecab/LGPL", "share/groonga/groonga-log/lgpl-2.1.txt")
        make(self.path, extra={p: b"complete legal body" for p in paths})
        result = self.report()
        self.assertEqual(result["licenseNoticeCandidatesCount"], 6)
        docs = {r["path"]: r for r in result["licenseNoticeFiles"]}
        for path in paths:
            self.assertEqual(docs[path]["sha256"],
                             hashlib.sha256(b"complete legal body").hexdigest())
        self.assertFalse(result["licenseNoticeClosureVerified"])
        self.assertFalse(result["redistributionAuthorized"])

    def test_empty_or_oversized_alternate_license_body_fails(self):
        for path in ("share/mecab/BSD", "share/mecab/GPL", "share/mecab/LGPL",
                     "share/groonga-log/lgpl-2.1.txt"):
            for data in (b"", b"X" * (audit.MAX_LICENSE + 1)):
                make(self.path, extra={path: data})
                with self.assertRaises(ValueError):
                    self.report()

    def test_generated_legal_retains_mixed_gem_terms_and_exact_document_hash(self):
        data = (b"MRuby license body\n\nAdditional Licenses\n\n"
                b"Generated license declarations:\n\n"
                b"GEM: mruby-pp\nCopyright (c) 2026 Authors\nLicense: BSD-2-Clause\n\n"
                b"GEM: mruby-dir\nCopyright (c) 2026 Authors\nLicense: MIT and MIT-like license\n")
        make(self.path, extra={audit.MRUBY_LEGAL_PATH: data,
                               "bin/legal-vendor.dll": b"MZ:vendor"})
        result = self.report()
        self.assertEqual(result["licenseNoticeCandidatesCount"], 3)
        self.assertEqual(result["binaryMemberCount"], 3)
        self.assertEqual(result["embeddedGemLicenseClaimsCount"], 2)
        rows = result["embeddedGemLicenseClaims"]
        self.assertEqual([r["licenseClaim"] for r in rows],
                         ["MIT and MIT-like license", "BSD-2-Clause"])
        for row in rows:
            self.assertEqual(row["legalDocumentPath"], audit.MRUBY_LEGAL_PATH)
            self.assertEqual(row["legalDocumentSha256"], hashlib.sha256(data).hexdigest())
            self.assertIs(row["completeLicenseTextVerified"], False)
            self.assertIs(row["exactSourceToBinaryBindingVerified"], False)
        self.assertFalse(result["publicGetAuthorized"])
        self.assertFalse(result["licenseNoticeClosureVerified"])

    def test_malformed_duplicate_or_non_utf8_gem_claims_fail_closed(self):
        prefix = b"MRuby\n\nAdditional Licenses\n\n"
        claim = b"GEM: mruby-pp\nCopyright (c) 2026 Authors\nLicense: BSD-2-Clause\n\n"
        for data in (prefix + claim + claim,
                     prefix + claim.replace(b"License: BSD-2-Clause", b"License: "),
                     prefix + claim.replace(b"Copyright (c) 2026 Authors\n", b""),
                     prefix + claim.replace(b"mruby-pp", b"../escape"),
                     prefix + claim + b"\xff", prefix + b"GEM: unknown\n",
                     b"Unknown format", prefix + claim + b"\x00",
                     prefix + claim * 129):
            make(self.path, extra={audit.MRUBY_LEGAL_PATH: data})
            with self.assertRaises((ValueError, UnicodeError)):
                self.report()

    def test_empty_oversized_legal_or_unrelated_path_never_grants_gem_acceptance(self):
        for data in (b"", b"X" * (audit.MAX_LICENSE + 1)):
            make(self.path, extra={audit.MRUBY_LEGAL_PATH: data})
            with self.assertRaises(ValueError):
                self.report()
        make(self.path, extra={"share/unrelated/LEGAL": b"unattributed legal text"})
        result = self.report()
        self.assertEqual(result["licenseNoticeCandidatesCount"], 3)
        self.assertEqual(result["embeddedGemLicenseClaims"], [])
        self.assertFalse(result["licenseNoticeClosureVerified"])

    def test_duplicate_basename_retains_separate_receipts(self):
        make(self.path, extra={"lib/libgroonga.dll": b"MZ:distinct"})
        result = self.report()
        self.assertEqual(len(result["duplicateBinaryBasenames"]["libgroonga.dll"]), 2)
        self.assertEqual(len({x["sha256"] for x in result["binaryMemberReceipts"]
                              if x["path"].endswith("libgroonga.dll")}), 2)

    def test_traversal_duplicate_and_colon_rejected(self):
        for name in ("../escape.dll", "BIN/LIBGROONGA.DLL", "bin/evil:thing.dll"):
            make(self.path, extra={name: b"MZ"})
            with self.assertRaises(ValueError):
                self.report()

    def test_missing_extension_payload_rejected(self):
        for name in ("lib/pgroonga.dll", "share/extension/pgroonga.control"):
            make(self.path, remove=(name,))
            with self.assertRaises(ValueError):
                self.report()

    def test_empty_and_oversized_license_rejected(self):
        for data in (b"", b"X" * (audit.MAX_LICENSE + 1)):
            make(self.path, extra={"share/NOTICE": data})
            with self.assertRaises(ValueError):
                self.report()

    def test_exact_production_pin_required(self):
        make(self.path)
        with self.assertRaises(ValueError):
            audit.audit_members(self.path, 18)
        self.assertEqual(audit.PINS[18][0], 53826667)
        self.assertEqual(len(audit.PINS[18][1]), 64)

if __name__ == "__main__":
    unittest.main()
