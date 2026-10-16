# Issue #112 — original-archive compatibility fix for pg_bigm PG14 bridge

This is a narrowly scoped, **nonpublishing** fix to the previously merged
`distribution_historical_p1_bridge.py`. It changes **neither** the ordinary
P1 verifier nor the Promotion workflow or Publisher, the signed original
artifacts, Release, Catalog v2 record, P2, installation or distribution.

## Observed original inputs (2026-10-17 Work audit)

- New externally pinned `resume6` archive: SHA256
  `bc4f0ce2c43f246e2535510eb0bad34e380db15f6b57c97a831b3c42b8d37744`,
  1,860,126 bytes; 31 original payload files **plus exactly one** byte-identical
  root `EVIDENCE-MANIFEST.json` (32 total).
- Nested previously preserved archive: SHA256
  `738ca743532922330c7bfad620d90d2e893a75aad02650f9d3dbe8b8407da491`,
  1,740,900 bytes; 59 original payload files **plus exactly one** identical
  root `EVIDENCE-MANIFEST.json` (60 total).
- Separate PG14 archive: SHA256
  `4e126798ea4fa84b50c441143ff3294d675831843c3b2bb3e57ff8a2f30e9ba3`,
  533,654 bytes; 69 original files **plus one** self-manifest (70 total).
  The nested PG14 archive's bytes must equal the separately pinned original
  in full; any disagreement is DENY.
- All three historical archives use PAX `mtime`. Only the PG14 archive
  additionally needs the PAX `path` extension for exactly two canonical long
  archive members. The preserved PG14 `cli-cache/gh/.sigstore` directory is
  inspection-only; it is never extracted into the reconstructed verifier
  input or accepted by the ordinary ZIP/Catalog path parser.

## Exact fail-closed design

1. Accept normal concrete `Path` subclasses, while requiring that original
   evidence is an existing non-symlink regular file, with exact **externally
   pinned** size and SHA256.
2. Tar inspection remains bounded, streaming, nonextracting, and rejects links,
   devices, nonempty directory entries, duplicate/casefold member names, path traversal,
   malformed PAX, unknown PAX keys and oversize data. Only canonical PAX
   numeric `mtime` and PG14-specific byte-exact long `path` spellings may be
   read. The original complete archive byte digest is checked **first**.
3. Treat the root self-manifest as a separately authenticated **single**
   embedded file; compare its bytes to the original external manifest, then
   verify each listed payload size and SHA256. Neither count nor file-set
   verification permits any other unexpected file.
4. Fetch preserved PG14 ZIP, SPDX, Grype and unchanged checksum bytes only
   from the **externally pinned PG14 archive**; PG15–16 bytes only from the
   pinned previous audit; PG17–18 bytes only from the pinned resume6 GET
   directory. Compare the old PG14 archive nested within the prior tar to the
   independently supplied entire original archive byte-for-byte. Require
   identical Release numeric identities and original 15 `./basename`
   checksums over the **actual 15 original payloads**, before any cryptography.
5. Run the unchanged strict historical PG14 verifier against the preserved
   original 14-file snapshot, old receipt, original SHA-pinned TUF Root and
   exact pinned official `gh` executable; original push Run/attempt 1,
   both authentic SLSA v1 and SPDX 2.3 signatures, OIDC/X.509, signed ZIP
   subject, source and successful jobs must pass. The reexecuted receipt must
   equal the original 1,856-byte receipt. No synthetic receipt or mocked gh
   can authorize acceptance.

## Tests and private validation

The new `test_distribution_historical_p1_bridge_original_archive.py` is
fixture-only: path subclasses, PAX valid/invalid spellings, malicious path
replacement, links, duplicates, missing files, extra self-manifest entries,
forged nested manifests, PG14 wrong identity, root/signer/run/attempt replay,
failed/mismatched gh executable and publication/P2 nonimplication. A fixture
PASS is **never** real cryptographic evidence.

A separate private isolated real-original preflight on the patched (not yet
merged) script used all seven preserved pinned inputs and the same pinned
official gh, completed 16/16 original Asset hashing, 15/15 checksums,
SLSA v1 + SPDX 2.3, and returned exit **0**; stdout SHA256
`cf6ac7b50b992ee7927496f949ea0707d6412fc256e6d6800adc25d257847804`.
Patched script SHA256 before any protected-PR merge:
`be9010ba70a9f1f4b33116e3266d0bd0c1ab6bfca7f2f2958de9a165bdd916a6`.
The local test suite had 18/18 successful tests.

**Important:** Until the exact patched code is admitted by a protected PR,
App15368 required CI and a postmerge original-byte/real-crypto rerun, the
formal registry/counter remains **P1 0/70**, historical source **0/40**,
P1 BLOCKED, P2 NO-GO, fleet incomplete, publication/distribution **DENY**.
Even one successful PG14 source verification is not permission to admit any
other PG or extension or to waive failed `plpgsql_check` attempt 1.

No new all-extension offline ZIP will be published; in the future the CLI
may create a local PG-major-organized offline ZIP on the user's computer.
Existing individual GitHub Releases and Website remain unchanged.
