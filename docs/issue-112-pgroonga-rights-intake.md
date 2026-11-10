# Issue #112 — PGroonga 4.1.0 Windows original rights intake (nonpublishing)

## Exact scope and existing accepted technical proofs

Official PGroonga 4.1.0 has original Windows x64 release ZIPs for PostgreSQL 14–18. The version-specific size and SHA256 pins are encoded in `scripts/issue112_pgroonga_rights_audit.py`, matching the separately verified official Release asset metadata and PR #277.

Previously accepted technical evidence (do **not** re-run successful runs):
- Upstream detached OpenPGP .asc verification, anchored to the trusted Groonga signing fingerprint `2701F317CFCCCB975CADE9C2624CF77434839225`, original ZIP size, SHA256 and CRC: Catalog Run [42910014161](https://github.com/pgextwin/catalog/actions/runs/42910014161), original protected-main postmerge.
- Five disposable EDB Windows PostgreSQL PG14–18 SQL smoke jobs on the exact original package, `CREATE EXTENSION pgroonga`, version 4.1.0, index and text search: same postmerge Run.

## Incremental rights/notice intake

The `issue112-pgroonga-rights-inventory.yml` is separately path-triggered. It never modifies the shared issuer, signed Catalog, CLI, Website or public policy. It has `contents: read` only, no artifacts or Releases.

For **each** of the five pinned source ZIPs, the CI:
1. Receives only the fixed 4.1.0 first-party URL; verifies the complete original on-disk size and SHA256 before member inspection, checks bounded ZIP paths, duplicate filenames, CRC and member expansion.
2. Records every license/NOTICE/COPYING/copyright-named text member with its **exact path, byte length, SHA256 and opening text**. This reports **candidate** legal documents, not their completeness.
3. Records every DLL and EXE member with its independent **path, byte size and SHA256**, including duplicate basenames. Component identity, per-component license/NOTICE, producer provenance and Windows dynamic dependency closure explicitly remain **unverified**.
4. Exercises seven hostile offline tests, including traversal, case-collisions, missing payload, oversized/empty notice, baseline pin and non-authorizing flags.

Official primary-source references:
- PGroonga [License and bundled-component explanation](https://pgroonga.github.io/#license): PGroonga PostgreSQL license; separate terms for xxHash, Windows-bundled Groonga (LGPL 2.1), MeCab, NAIST dictionary, LZ4 and msgpack-c. This public list must **not** be treated as an exhaustive license BOM for these five exact 2026 binary ZIPs.
- [Upstream tagged Windows build source](https://github.com/pgroonga/pgroonga/blob/4.1.0/.github/workflows/windows.yml) documents building and installing Groonga alongside PGroonga, with bundled MeCab, msgpack, RapidJSON, xxHash and Zstd settings. Tag source and a release signature **do not** constitute a cryptographic provenance attestation for all bundled third-party binaries.
- [Official 4.1.0 Release](https://github.com/pgroonga/pgroonga/releases/tag/4.1.0) for original-asset provenance and hashes.

## Must remain blocked before formal admission

- Associate **each observed exact binary member** with actual component name/version/source, applicable license text, NOTICE/attribution and redistribution conditions; use separate independent review, not basename guessing.
- Trace static/delay imports and dynamic runtime dependencies on actual Windows/EDB targets. Prior SQL success proves only its tested paths.
- Establish exact producer/build/source-to-original-release provenance to the level required by the existing publisher policy; compare official tag build workflow and released asset identity, without inventing attestation.
- Only **after** independent rights, dependencies, provenance and provider-get acceptance, use a new authentic owner event, protected main, fresh qualified-cohort issuer, required Environment approval and independent Sigstore verification; create-only formal publisher and CLI E2E are separate gates.

Outcome here: **CANDIDATE_ONLY**, `PUBLIC_GET=DENY`, `MIRROR=DENY`, `RELEASE=DENY`. Existing CLI v0.3.13's earlier PUBLIC_COMPLETE scope remains unchanged. OSGeo remains an independent CANDIDATE_ONLY investigation.
