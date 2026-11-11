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

## MRuby generated LEGAL correction (2026-11-11)

The 24-document legal-name inventory was incomplete: the exact PG18 original
also contains `share/groonga/mruby/LEGAL`, 3,502 bytes, SHA256
`020dcd4ec1ee0826cb5cb4ee61f6dacb5a7786a9ff4e27335bf0e4c51dc47b56`.
It starts with an MIT text and declares **31 gems**, including 26 core gems
and five additional gems. The auditor now hashes LEGAL and emits bounded,
document-hash-linked `embeddedGemLicenseClaims`. Duplicate, malformed,
non-UTF-8, empty and oversized LEGAL inputs fail. License labels and generated
copyright claims do not establish complete original terms or binary provenance.

| Original LEGAL gem | Original declared license | Fixed candidate source |
| --- | --- | --- |
| mruby-dir | MIT and MIT-like license | MRuby core; separate notice review required |
| mruby-pp | BSD-2-Clause | [kou/mruby-pp@a208b14886e664785b4722dc076e4d33f2fbd1e9](https://github.com/kou/mruby-pp/tree/a208b14886e664785b4722dc076e4d33f2fbd1e9) |
| mruby-tsort | BSD-2-Clause | [kou/mruby-tsort@29e87327387c9c878b05cb259c91b74ac73ea997](https://github.com/kou/mruby-tsort/tree/29e87327387c9c878b05cb259c91b74ac73ea997) |
| mruby-slop | MIT | [kou/mruby-slop@38f4795712c8f92e4c9412b5fc81646b3972b12a](https://github.com/kou/mruby-slop/tree/38f4795712c8f92e4c9412b5fc81646b3972b12a) |
| mruby-file-stat | MIT | [ksss/mruby-file-stat@7d0e63a95a38b34c635b708874ec624c7c860507](https://github.com/ksss/mruby-file-stat/tree/7d0e63a95a38b34c635b708874ec624c7c860507) |
| mruby-onig-regexp | MIT | [mattn/mruby-onig-regexp@4962d7eb42de079f6b3faec4b40560eb2941eeec](https://github.com/mattn/mruby-onig-regexp/tree/4962d7eb42de079f6b3faec4b40560eb2941eeec) |

The fixed Groonga **source-review candidate** `9085dd417e5cd42cd8f1a367aaf24cfe45dd9f1f`
has gitlinks for those five repositories. Its `vendor/mruby/build_config.rb`
declares exactly the 31 gem names observed in the original LEGAL, and its CMake
installs LEGAL separately from MRuby LICENSE. Each of the five pinned gem specs
declares the same license label as LEGAL. All **16 retrieved source files**
independently match their Git blob SHA1; byte lengths and SHA256 are recorded in
[source comparison receipts](../evidence/issue112-pgroonga-mruby-source-review.json).
This is **not** proof of the historical mutable `groonga-latest.zip` contents.

The pp/tsort source LICENSE files contain BSD conditions and original copyright
holders that must not be replaced by generated 2026 author lines. The slop source
LICENSE also has its own historical attribution. None of those three *whole
source license texts* matches a bounded nonbinary original member even after
newline normalization; this comparison does not exclude equivalent terms
embedded inside another member. file-stat's fixed README points to mutable
Ruby `trunk/file.c`, so its MIT spec alone does not settle inherited source
terms. onig-regexp's README separately mentions Onigmo's terms.

Local exact PG18 inventory: **43 binaries / 25 legal documents / 31 gem claims**;
strict joins pass, with 13 documents outside direct binary-name triage. Other PG
majors require their own scoped CI evidence. Source-to-binary binding, all
applicable notice delivery (including xxHash), NAIST and remaining static/header
terms, formal admission and public GET remain unfulfilled. No original ZIP or
third-party source/license text is mirrored by this change.

## Fixed core terms and companion-notice preparation

The [fixed source-terms review](issue-112-pgroonga-source-terms-review.md)
distinguishes MRuby's upstream source LEGAL from its generated package LEGAL,
reviews Windows mruby-dir and compiler copyright notices, confirms file-stat's
Ruby origin in source, and prepares seven complete fixed candidate notice
texts. Nine source Git blobs are independently checked. PG18 cached-original
substring scans and their limits are recorded separately from prior five-major
inventory evidence. Companion delivery, historical input authentication,
all-component rights/provenance and public admission remain unresolved.
