# External Windows binary discovery and selection (Issue #112)

Status: **CANDIDATE_ONLY, metadata/read-only; no new download authority, mirror, install or Release.**

## User-facing contract

The user sees only two source groups: **external** (upstream or community-provided
Windows binary) and **pgextwin** (both adapted/reference-based and native builds).
Adapted and native are pgextwin's internal implementation methods, not
competing user-facing products. Website cards should prioritize extension name,
upstream stable version, supported PostgreSQL major, compatible Windows x64
environment, provider, availability, and a verified download action. Do **not**
dump candidate-rejection explanations, upstream reference history or builder
internals onto Website cards. Put the provenance, considered approaches,
reasons for non-adoption, licenses, dependency requirements and reproducible
evidence in the repository README and technical documentation. Release notes
should describe only visible changes to availability, usage or compatibility.

For ambiguous download paths, expose **only** an artifact that passed independent
trust/compatibility/rights gates. A discovered-but-unreviewed external file is
searchable as *not yet available*, not offered as an approved download.

## Contract and precedence

1. Filter by extension, PG major, architecture, PostgreSQL distribution, ABI,
   dependencies, rights, original ZIP SHA256, source identity and provenance.
   PG major alone is **not** an ABI compatibility claim.
2. Among eligible candidates select the **latest stable upstream version**;
   within that exact version and environment rank
   external > adapted > native.
3. At identical external rank, prefer independently verified upstream-official
   over independently verified community sources, then use a deterministic
   provider/ID tie-break. Unknown verification does not gain priority merely
   from an upstream-official label.
4. An older official Windows ZIP **must not** hide a newer eligible pgextwin
   build. Source selection is by extension version+PG environment, not a
   permanently fixed per-extension provider. A newly published official build
   can become a candidate after authentic Catalog refresh and independent gates.
5. Historical versions, including EOL PG binaries, remain discoverable; require
   explicit exact-version and EOL opt-in for selection. Do not build new EOL
   targets by default. Nothing silently overwrites or deletes old native
   Releases or installed files.
6. Admission filtering may exclude unverified candidates *before* selection.
   Once a candidate is selected, download, hash, Sigstore, dependency or network
   failure terminates the transaction: **no implicit fallback**.

## Registry and security boundary

- evidence/issue112-external-release-inventory-20261103.json contains the
  complete two-page-per-source authenticated GitHub Release **metadata** GET
  for three pilot providers. It is a finite, audited discovery snapshot, not
  proof of exhaustive external Internet coverage.
- external/windows-candidates-v1.json flattens every identified Windows
  ZIP/EXE into a versioned candidate with separate release tag, asset version,
  PG major, architecture, provider/source repository, release/asset numeric
  IDs, API-provided digest (if present), original independently rehashed SHA256
  (currently null), compatibility, dependencies, license, lifecycle, verification
  and separate direct-download vs mirror authority. Historical/EOL and missing
  digest entries are retained; **all current entries are metadata-only and
  download DENY**. An API digest is not independent raw-byte verification.
- schema/external-windows-source-v1.schema.json is additive; original
  Catalog v2 index.json/extension shape, signed feed ZIP pins and
  download-all --fixed remain unchanged. The optional
  externalSourceRegistry link is purely descriptive and cannot grant trust.
- WindowsSourceSelector is a pure, network-free selection function intended
  for use **only after an independently authenticated, gate-approved snapshot**.
  It has hostile synthetic tests covering version ordering, current vs old
  official, PG/ABI mismatch, dependency and identity failure, EOL and no fallback.
  The local registry reader deliberately never creates an authorized ZIP pin.

### Current CLI

list/search --catalog-dir PATH --source external|pgextwin|all performs
**local untrusted discovery**, and optional --format json returns explicitly
untrusted result sets. --source omitted keeps the old listing format.
download and download-all with --source pgextwin retain the existing
pgextwin path; --source external|all is intentionally denied until a protected
Catalog commit, signed external feed extension and independent original-byte,
identity, rights, ABI and provenance verification authorize the chosen file.
Existing source-omitted latest mode, download-all --fixed, staging, checksums,
rollback, and failure isolation are untouched. This PR is **not** a new
downloadable CLI release.

### Pilot evidence and blockers

- HypoPG upstream 1.4.1 has historical PG14-16 Windows assets; upstream 1.4.5
  has no comparable official Windows ZIP. The newer pgextwin 1.4.5 remains
  preferred. This is a metadata comparison, not an ABI compatibility approval.
- oracle_fdw upstream 2.9.0 publishes PG14-18 Windows ZIPs. PG18 Release ID
  335861225, Asset ID 442625860, and GitHub API SHA256
  ad1fc057888b89f968de34f14bd7088c2b05d674a8df4b40ba47ed772c317678
  identify a **candidate**, and independent SHA256/ZIP CRC bytes passed in the read-only
  GitHub Actions pilot. Oracle Instant Client compatibility, license and
  signer provenance are not verified.
- A community pgvector Windows repository
  andreiramani/pgvector_pgsql_windows has version 0.8.7 ZIPs for PG13-18.
  This is **unofficial**; its PG18 ZIP original SHA256 and CRC passed the
  read-only GitHub Actions pilot, but signature, ABI and source provenance
  acceptance remain blocked.
- Read-only GitHub Actions Run 41638680503 (attempt 1) at commit
  db39ed5ff289f1d6ada4817dcdb28f5a1d6e9acd verified the original ZIP
  SHA256, CRC, member structure and bounds for **both** pilots. This is a
  genuine byte-integrity check, NOT Sigstore/identity/ABI/license acceptance.
  Evidence: evidence/issue112-external-original-byte-pilot-20261103.json.
  Candidate admission remains blocked even after the bytes match.

## Remaining integration

Extend the **authenticated, versioned** Catalog feed with admitted candidate
pins only after full validation, extend the existing batch downloader to consume
selected pins without source-specific bypasses, run actual Windows verified
official + community ZIP pilots and original postmerge tests, then separately
gate any mirror or formal Publisher publication. Do not rewrite old Releases.
