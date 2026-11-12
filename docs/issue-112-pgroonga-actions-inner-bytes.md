# Issue #112 — PGroonga 4.1.0 original Actions artifact to Release ZIP byte identity (deny-only)

**Scope: CANDIDATE_ONLY. PUBLIC_GET / MIRROR / RELEASE / PUBLISH DENY.**
This documents independently rehashed original (not re-run) upstream GitHub Actions outer artifact ZIPs. It does not replace the signed producer input, owner, licensing or Publisher acceptance.

## Verified original bytes, PG14–18

The authenticated upstream original Windows [Run 37872644159](https://github.com/pgroonga/pgroonga/actions/runs/37872644159) attempt 1, source commit 47d0252f76dccbdc2ebeee9ed6cf941dd9552bcc, produced five artifacts. On 2026-11-13 JST, the five **existing** upstream Actions artifacts were downloaded via GitHub's artifact-download facility, and both outer and inner SHA256/size were independently streamed on disk. Each outer ZIP contains exactly one inner member named pgroonga-4.1.0-postgresql-<PG>-x64.zip; each inner byte hash exactly matches the separately pinned **official Release 4.1.0** original ZIP. No Actions job was rerun or upstream artifact changed.

| PG | Original Actions artifact ID | Outer ZIP bytes | Outer ZIP SHA256 | Inner official ZIP bytes | Inner official ZIP SHA256 |
| -- | --: | --: | -- | --: | -- |
| 14 | 11590129653 | 53261546 | 39e3a50fb8aa857e007f2af42f103824b0eb54c0091dd345db941851b05c3088 | 53806600 | 39d2685f234c8b45563f57f113bd8c84cc1ae4e8c0c22e6826bf168ba1c0ab39 |
| 15 | 11590989124 | 53317133 | 8cbd5a43aba3ebb4ec360709db6aa077925ce7a6109da33c7024f694e6074d38 | 53863529 | fbc73734028b0b2372a6ee6538863999c2f9f06ec9f1be633ac460c7d8a0d4f1 |
| 16 | 11590348972 | 53205129 | 552959c27733e0b1c789a426bb383da4acf04bb6fb42f13217bb3880d60a4c5e | 53751780 | 40c71f7890e6ceb46f79fdc10e596da21bfb622f7c9d1f8be7784175d96df7e8 |
| 17 | 11591150953 | 53294168 | 0a32411389a3a81a48fffb520d1bab5963676df0a74493e38e3b4a79f35e1e84 | 53836587 | dcbd356ab8a7c8fc3a3cc7082b4f99a1884b5a68674e25ef4bbe56583c38147b |
| 18 | 11590859682 | 53278986 | fe6388d9928fda9f1d2a350e7dc6a30200ebd9f6c933e008f02315dced444c91 | 53826667 | 3ccbfaf771ec7a0edf61dabe0eb60188dcc22feff8449a7e96afdb87641630ab |

This establishes **original Actions artifact inner ZIP bytes = pinned official Release ZIP bytes**. It is stronger than matching Actions API metadata to Release metadata, but is not a signed statement of original source inputs.

## Reusable fail-closed verifier and tests

With the original outer artifacts locally available, run the new scripts/issue112_pgroonga_actions_inner_bytes.py using --all-dir DIRECTORY (files pgroonga-upstream-original-pg14.zip through pg18.zip) or --pg 18 --artifact PATH. It reuses immutable producer artifact IDs/outer expected hashes and independently pinned official Release ZIP hashes from existing Catalog auditors. It rejects wrong PG, truncated/oversized/tampered outer artifacts, wrong/multiple inner members, unsafe ZIP member types, encryption, wrong inner size/hash and duplicate report majors. It neither downloads nor uploads nor publishes bytes.

The path-scoped new GitHub CI tests **adversarial offline fixtures**, not a claim that original upstream artifacts were downloaded inside CI. The five real byte-rehash observations above were performed separately. This avoids requiring a cross-repository artifact-read token in Catalog's regular CI and preserves the distinction between original evidence and simulation. All checks are nonpublishing and use contents:read.

## Residual BLOCKED requirements

The upstream immutable workflow still fetched mutable https://packages.groonga.org/source/groonga/groonga-latest.zip without pinning its historical SHA256; its upstream tag was unsigned and the Release workflow selected a run by query. No complete signed original build-input-to-binary attestation has been established. The verified detached OpenPGP signature on the *final* ZIP covers a different trust boundary. xxHash binary-redistribution license text delivery in the original ZIP, MRuby and other transitive third-party rights, dynamic imports, owner-signed source-specific GET approval and dedicated Publisher authorization remain unverified.

This is **NONPUBLISHING byte-provenance evidence only**. The five matches never grant signed input lineage, complete legal rights, source-specific GET admission, mirror authorization, Release or Publisher permission. No CLI, public feed, ZIP, issuance policy, Website or distribution path was changed.
