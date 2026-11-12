# Issue #112 — PG14 EOL signed-feed CLI transition / rollback acceptance

**State: migration ACCEPTANCE PENDING until genuine CI/E2E outcomes.**
This document does not authorize publication of any external candidate,
extension ZIP, mirror, or CLI Release, and does not request a Run rerun.

## Known public source identities (authenticated GitHub inspection)

| Immutable CLI tag | `dotnet/src/PgExtWin.Releases/SignedPublicCatalogFeed.cs` blob | Code-level result for retained PG14 Catalog entries and four-major latest feed |
| --- | --- | --- |
| `cli-v0.3.13` | `ec3c624a204b61c0958379676bc757c5b0a8e4b6` | Requires `x.Versions.Count == majors.Length` and exact sequence. Retained five-major Catalog records cause fail-closed latest selection with four-major feed. **Not a supported latest rollback.** |
| `cli-v0.3.14` | `eabedf7a07f51bc001def6a9f7779b115853f3b8` | Requires all signed majors, permits older historical majors. Source is compatible; binary E2E still requires genuine acceptance. |
| `cli-v0.3.15` | `eabedf7a07f51bc001def6a9f7779b115853f3b8` | Same source-level migration logic; public binary exists, but actual **post-#313** latest ZIP cohort acceptance must be checked. |

Protected signed-feed policy `config/cli-feed-majors.json` now lists
PG15–18. [Feed Release `catalog-feed-67dc29a1...`](https://github.com/pgextwin/catalog/releases/tag/catalog-feed-67dc29a13c7034bc15a32473fefed0cd474b5190)
was published after PR #313, with 17 extensions / 68 ZIP metadata rows
reported by the signed-feed issuer. Archived PG14 Catalog records are
intentionally still present, but **PG14 is absent from the latest signed
cohort**. The old `--fixed` route uses separate immutable historical
selection and must be tested on genuine released binaries before claiming
a verified rollback. A source-level proof alone does not prove a binary run.

## Real Windows acceptance contracts amended in this PR

- `.github/workflows/cli-anonymous-latest.yml`: actual anonymous latest
  original ZIPs, no GitHub token; no five-major count assumption.
- `.github/workflows/cli-authenticated-latest-canary.yml`: current source
  CLI against genuinely signer-approved latest cohort, no five-major assumption.
- `.github/workflows/cli-published-e2e.yml`: original published EXE and
  real ZIPs; triggers on protected main after this workflow change.

Each now locates the **actual atomic cohort directory** (e.g.
`pgextwin-pg15-18`), obtains the exact immutable source commit claimed by
the Sigstore-verified feed from the CLI output, reads that source's
`config/cli-feed-majors.json`, and asserts: (1) reported majors equal the
policy, (2) each extension/major pair is unique, (3) ZIP count matches the
cross-product, and (4) output folder agrees. The existing per-ZIP actual
SHA256, release identity, immutable Catalog and nonpublishing receipt checks
remain unchanged. This fetch is *test corroboration only*; it cannot
override the CLI's Sigstore or original-byte validation.

## Interpretation / safe migration

1. The **default latest command** on v0.3.13 is a known incompatible rollback
   under PG15–18 feed with preserved PG14 records. Never silently substitute
   another feed, suppress an integrity error, or claim successful rollback.
2. v0.3.14 and v0.3.15 source contains the compatibility change, but
   production readiness is decided by the successful genuine public EXE
   main-push E2E and exact head evidence, **not** merely static source equality.
3. For historical PG14, explicitly request `--fixed` on a compatible
   released CLI. A real independent PG14 ZIP/receipt acceptance and
   downgrade/rollback execution are **still pending** in this cycle.
4. A failure/skipped acceptance is a blocker; do not rerun a previously
   successful Run, bypass signature gates, or call a metadata-only signed
   feed an authorization of new external provider ZIPs.

Regression contract: `python -m unittest discover -s tests -p
'test_issue112_pg15_signed_feed_smoke.py'`. A regression-test PASS means
workflow expectations were updated, **not** that the real Windows jobs passed.

## Independent legacy *published EXE* rollback acceptance

The [read-only rollback E2E workflow](../.github/workflows/issue112-cli-legacy-rollback-e2e.yml)
tests the exact, previously published v0.3.13 and v0.3.14 Windows EXE
bytes with fixed per-release SHA256, size, immutable tag and release
commit. It additionally runs genuine Sigstore verification on each
EXE's original producer claim. No synthetic or private build may
substitute for those released EXEs.

- v0.3.13: the current four-major latest feed with historically retained
  PG14 Catalog records must **fail closed**, leaving no committed output.
  `--fixed --pg 14` must independently obtain and hash 14 historic ZIPs
  using the old CLI's immutable pinned source. This is a **legacy
  retrieval fallback**, not a public authorization to publish PG14 again.
- v0.3.14: `--latest --pg 15` must obtain and independently hash 17
  original ZIPs from the current four-major Sigstore-verified feed.
  This can establish a compatible downgrade alternative *if* real CI
  passes.

Never claim a rollback is accepted until both original Release-tag
identity and the respective **real** Windows job conclude SUCCESS.
No token is supplied to the CLI under test; no Release, policy, mirror,
provider admission, or publisher authorization is created.
