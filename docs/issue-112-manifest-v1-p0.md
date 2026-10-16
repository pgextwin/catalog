# Issue #112 — Manifest v1 P0 (nonpublishing)

## Read-only inventory, 2026-10-16

- Protected Catalog main: 098b0175bc6b5f785b0df0437f14980495067024; required validate = GitHub Actions App 15368.
- Protected build main: 0466d7275473cd88a95de650c4ac002c7941a67f; required resolver = GitHub Actions App 15368.
- Catalog v2 index has exactly 14 extensions. Latest public formal Releases expose 5 ZIP + 5 SPDX + 5 Grype + SHA256SUMS per extension: 70 ZIP, 224 named assets.
- All 70 ZIP Release metadata digest fields agree with Catalog SHA256 metadata. This is NOT 70/70 independently rehashed bytes or 70/70 cryptographic attestations.
- The Catalog records lack full per-major upstream commit and mostly upstream ref; these must be derived and verified from immutable upstream/source PACKAGE-INFO/provenance. Never infer from Release tags.

| Extension | Latest Release | Release ID |
|---|---|---:|
| hypopg | v1.4.3-windows.1 | 408798350 |
| orafce | v4.16.13-windows.1 | 409043426 |
| pg_bigm | v1.2-20250903-windows.2 | 408449466 |
| pg_cron | v1.6.8-windows.2 | 408447762 |
| pg_hint_plan | v1.8.0-windows.2 | 408447843 |
| pg_ivm | v1.16-windows.2 | 408456115 |
| pg_partman | v5.5.0-windows.2 | 409245095 |
| pg_qualstats | v2.1.4-windows.2 | 408453847 |
| pg_repack | v1.5.3-windows.2 | 408452263 |
| pg_stat_monitor | v2.4.0-windows.1 | 409069791 |
| pgaudit | v18.0-windows.2 | 408453283 |
| plpgsql_check | v2.10.14-windows.1 | 409572202 |
| set_user | v4.2.0-windows.2 | 408453245 |
| wal2json | v2.7-windows.1 | 410447206 |

## Interface and non-authority

JSON Schema Draft 2020-12 defines closed objects for root, per-PG package/version/ref/full SHA, original Release and asset numeric identities/digests, SPDX/Grype/attestation bundle hashes, runtime, license/NOTICE, PG EOL, coverage and snapshot. Strict generator uses exact authenticated Catalog commit and byte-preserving index/record hashes. Snapshot ID is SHA256 of canonical JSON with sorted keys and terminal LF, excluding snapshotId. Caller supplies canonical UTC time for deterministic reproducibility.

The generator requires a separately authorized major policy and an injected independent verifier callback. No network or verifier implementation is shipped. Missing pins, receipts or failed callback produce blocked coverage, not a signed package. Synthetic tests use a stub callback only to exercise the pure projection. A callback returning True is NOT itself a cryptographic verification and must never be wired to user input or used to publish.

Re-use scripts/verify_signed_fleet_release.py only as a read-only source verifier (original published ZIP byte hashes, SHA256SUMS, PACKAGE-INFO, SPDX, Grype, signed main Promotion/attempt and gh attestation verify). Never call its Catalog record-write pathway; never reuse unsigned or mixed-attempt CI. Offline verification must independently authenticate trusted-root material, Catalog source, actual asset bytes, provenance and SBOM attestation subjects, numeric build-signing repository ID 1405931353, OIDC issuer, workflow, main ref, source repository IDs and predicates. An untrusted archive cannot authenticate itself with checksums or trusted roots contained inside it.

Trust scope is permanently NONPUBLISHING_P0 in this schema: outerArchiveSigned=false, offlineTrustRoot=EXTERNAL_REQUIRED and publicationAuthorized=false. The P0 schema can express a verified fixture package, but cannot authorize a bundle or installer. Validating a schema is not validating a cryptographic signature. Catalog metadata equality is not integrity verification.

Archive layout: packages/pg<major>/<extension>/<per-major-version>/<original-asset-name>.zip. Static ZIP inspection rejects duplicate/case-fold collisions, unsafe/absolute/traversal paths, Windows device aliases, symlinks/devices, encryption, oversize and compression bombs. Future pilot must additionally independently verify bytes/CRC, nested extraction, PACKAGE-INFO/PG identity, paths at extraction and global budget; static checks are not sufficient to install.

## Next gates

1. Independent GET-only authenticated source + Sigstore verifier adapter; nonpublic 70/70 byte rehash and evidence proof; no public entrypoint.
2. Offline trust bootstrap from independent authenticated root and digest. Reject untrusted/expired roots, valid signatures from wrong repo or workflow, signature replacement and PG mismatches.
3. Separate P2 local bundle, P3 CLI, P4 safe installer, P5 restricted signed-bundle publication gate; no GO A/GO B/G4/G5 transition by this PR.
4. PG14 maintained until 2026-11-12 inclusive UTC; historical from 2026-11-13. PG19 2026-10-15 RC1 not GA, GA planned 2026-11-19; no PG19 distribution approval.

Publication decision: DENY. No formal Releases, tags, signing, Dispatch, billing, Secrets or protected settings changed.
