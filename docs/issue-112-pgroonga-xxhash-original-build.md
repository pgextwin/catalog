# Issue #112 — PGroonga 4.1.0 original Windows producer logs: xxHash (nonpublishing)

This is new read-only **official primary-source** evidence, linked to the existing [43-binary-to-20-doc path-exact candidate ledger](issue-112-pgroonga-rights-join.md). It does **not** accept rights, authorize external GET, establish a Sigstore attestation or replace the original signed-byte review.

## Exact original official upstream event (2026-10-09 UTC)

- Annotated upstream tag [`pgroonga/pgroonga@4.1.0`](https://github.com/pgroonga/pgroonga/releases/tag/4.1.0) resolves to commit `47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc` (annotation Git object `a40db64f8e4761d3dc00b457faabf00d0613a711`). The original [Windows Run 37872644159](https://github.com/pgroonga/pgroonga/actions/runs/37872644159) is **push / attempt 1 / completed SUCCESS** at that commit. These original jobs were read, **not rerun**.
- Every PostgreSQL 14–18 upstream Windows job completed SUCCESS. Its **Groonga CMake** portion reported `No xxHash` even though the workflow passes `-DGRN_WITH_XXHASH=bundled`. Its separate **PGroonga Meson** portion resolved `libxxhash` via fallback at **0.8.3**, linked `subprojects/xxHash-0.8.3/libxxhash.dll` and `subprojects/xxHash-0.8.3/xxhsum.exe`, then installed both into that PG-specific release staging `bin`.
- The exact tagged [PGroonga xxhash.wrap](https://github.com/pgroonga/pgroonga/blob/47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc/subprojects/xxhash.wrap) independently specifies `directory = xxHash-0.8.3`, `source_url = https://github.com/Cyan4973/xxHash/archive/v0.8.3.tar.gz`, `source_hash = aae608dfe8213dfd05d909a57718ef82f30722c392344583d3f39050c7f29a80`, and a separately hash-pinned Meson wrapdb patch. These **source pins are not hashes of the published Windows DLL**.
- Original component author's [xxHash v0.8.3 LICENSE](https://github.com/Cyan4973/xxHash/blob/v0.8.3/LICENSE) states a **BSD 2-Clause** notice requirement for binary redistribution. This license is an **external candidate source**, **not** one of the 20 named license/NOTICE documents actually observed in each published PGroonga ZIP. A generic Groonga COPYING is not substituted for it.

| PG major | Exact original Windows job | Meson xxHash | Groonga CMake | Staged binaries |
| --- | --- | --- | --- | --- |
| 14 | [113633984915](https://github.com/pgroonga/pgroonga/actions/runs/37872644159/job/113633984915) | 0.8.3 | No xxHash | libxxhash.dll + xxhsum.exe |
| 15 | [113633984767](https://github.com/pgroonga/pgroonga/actions/runs/37872644159/job/113633984767) | 0.8.3 | No xxHash | libxxhash.dll + xxhsum.exe |
| 16 | [113633984557](https://github.com/pgroonga/pgroonga/actions/runs/37872644159/job/113633984557) | 0.8.3 | No xxHash | libxxhash.dll + xxhsum.exe |
| 17 | [113633984752](https://github.com/pgroonga/pgroonga/actions/runs/37872644159/job/113633984752) | 0.8.3 | No xxHash | libxxhash.dll + xxhsum.exe |
| 18 | [113633984742](https://github.com/pgroonga/pgroonga/actions/runs/37872644159/job/113633984742) | 0.8.3 | No xxHash | libxxhash.dll + xxhsum.exe |

**Do not conflate the two build stages.** A Groonga source tag's `bundled_xxhash_version` (for example 0.8.2 in v16.1.3) does not override the PGroonga Meson 0.8.3 original-job observation. Conversely, the `groonga-latest.zip` download is mutable, unpinned by upstream workflow; the exact Groonga source SHA and source-to-original-ZIP component provenance remain unknown.

## Other exact upstream run output (configuration-level hints only)

All five original jobs also report **Zstandard 1.5.7** (bundled), **xsimd 14.0.0** (bundled), **ggml 0.9.7** (bundled llama.cpp), and **jsoncons 1.7.0** (bundled). Groonga CMake also reports MeCab, MessagePack, simdjson, H3 and llama.cpp as bundled, but these lines do **not** identify their exact versions or prove complete licensing/NOTICE closure. No provenance or runtime acceptance is inferred for the ZIP's other 41 binaries or statically embedded libraries.

## Remaining independent gates (unchanged)

The exact signed-upstream ZIP receipts (five SHA256/size pins, each with 43 binary and 20 named-rights-file members), proof of actual binary content and functional SQL tests are separate from producer log observations. Actual release ZIP bytes must still be cryptographically bound to original producer evidence; each library's license/NOTICE must be satisfied, including xxHash; mutable Groonga source SHA, all other component versions, static and dynamic dependency closure, independent signer and authorized qualified_cohort/Publisher remain unverified. All `exactComponentVersionVerified`, `componentLicenseNoticeVerified`, `sourceToBinaryProvenanceVerified`, `publicGetAuthorized`, `mirrorAuthorized`, and `publisherAuthorized` flags remain **false**. No original ZIP or third-party license is redistributed by this audit.

**Decision: CANDIDATE_ONLY / PUBLIC_GET_DENY / MIRROR_DENY / RELEASE_DENY.** No signer, owner event, Environment or Publisher action occurs.
