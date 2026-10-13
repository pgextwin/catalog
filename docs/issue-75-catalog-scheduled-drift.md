# Issue #75 — Catalog wal2json read-only scheduled drift pilot

Status: **INERT scheduled GET-only pilot**, not an automatic Release, signed-release verifier,
GitHub App proposal or Catalog PR/mutation. 
Time: daily at **00:30 UTC / 09:30 JST**, GitHub schedule is best effort. A one-time
main-push path-only run proves the same runner on an actual protected Catalog main.

## Existing code reused

- `scripts/catalog_release_drift.py` strictly compares verified-format public
  stable Release metadata to `catalog/extensions/wal2json.json`, rejecting duplicate
  Release tags, malformed timestamps, backward chronology and ambiguous history.
- `scripts/catalog_drift_live_readonly.py` re-reads authoritative Catalog main,
  Git blob SHA, current 100-entry public Release history, and every open Catalog
  PR's changed files. API errors, redirects, duplicate JSON keys, oversized data,
  unsafe endpoints or incomplete pagination DENY. A PR touching the same record
  is treated as a conflict, not an instruction to create a duplicate PR.
- `scripts/catalog_scheduled_readonly.py` collects **two complete independent**
  authenticated GitHub snapshots and refuses main, Release or open-PR TOCTOU.
  It accepts only `NO_CHANGE`, `VERIFY_SIGNED_RELEASE_FIRST` and
  `BLOCKED_OPEN_RECORD_PR`. All three states are still nonpublishing:
  `verifiedSignedRelease=false`, `proposalAuthorized=false`,
  `mutationsEnabled=false`, `publishableReceipt=false`.
- `.github/workflows/catalog-drift-readonly.yml` is limited to
  `schedule` + protected `main` `push` of **that exact workflow path**,
  with `contents:read` only and pinned Actions. No `workflow_dispatch`,
  write token, App secret, `gh pr`, `gh release`, tag operation or artifact
  upload. `GITHUB_TOKEN` is used only for GETs of public releases and metadata.
  A `VERIFY_SIGNED_RELEASE_FIRST` result means a future **independent** signed
  Release verifier is needed; this pilot never invokes or authorizes one.

## Real wal2json baseline

As of 2026-10-13, independently checked public
`pgextwin/wal2json` Releases include `v2.6-windows.1` and newest
`v2.7-windows.1`, published at `2026-10-12T09:46:28Z`.
The protected `pgextwin/catalog/main` record
`extensions/wal2json.json` contains `v2.7-windows.1` with the same
publication timestamp. No open Catalog PR touches that record
(the only open PR at checkpoint was unrelated Dependabot #11).
Expected live result is `NO_CHANGE`, which is **metadata agreement only**,
not a new SHA256/ZIP/SBOM/Grype/attestation verification. A new public
Release would be classified as `VERIFY_SIGNED_RELEASE_FIRST` without
creating a candidate or PR.

## Acceptance and rollback

The required `validate` GitHub Actions check (app id `15368`) must PASS
on the exact PR head before expected-head squash merge. After merging, the
main-only path push run must confirm the actual authenticated
`NO_CHANGE` from **two** snapshots. Keep the existing Catalog
`sync-verified-release.yml` manual mode and disabled-by-default
auto-merge settings untouched. A schedule does not guarantee an exact
fire time; future schedule acceptance requires an actual observed run.
The pilot intentionally covers wal2json only, **not 14/14 rollout**.
If a change is needed, use a protected PR; never bypass main required CI.

Issue #75 remains OPEN until an eligible signed future Release has been
explicitly authorized and independently propagated through Catalog and
Website without unauthorized Dispatch or publication.
