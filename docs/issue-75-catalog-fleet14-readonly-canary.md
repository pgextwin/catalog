# Issue #75 — 14-extension Catalog metadata one-shot acceptance

Status: **NONPUBLISHING / NO NEW FLEET SCHEDULE / ONE-SHOT main-push acceptance**

## Current checkpoint

- `catalog/main@e32cc0a199b77d2e04370eb23159fa199f90347c` is protected with required GitHub Actions `validate`. Only unrelated open Dependabot PR #11 at the planning checkpoint.
- Existing `.github/workflows/catalog-drift-readonly.yml` remains the sole 09:30 JST scheduled **wal2json-only** read-only audit. Its protected-main `push` run [38411069849](https://github.com/pgextwin/catalog/actions/runs/38411069849) verified actual `NO_CHANGE`, two snapshots, `publishableReceipt=false`. At the Oct 13 JST checkpoint no `event=schedule` run had yet occurred after its installation; next nominal occurrence is Oct 14 09:30 JST, subject to GitHub scheduler delays.
- A separate informal read-only lookup of all 14 latest public GitHub Release tags found matching `catalog/extensions/*.json` current tags. This is **not** a signed-asset or complete two-snapshot 14-fleet proof.

## Narrow code reuse

- `catalog_scheduled_readonly.audit(api, extension="wal2json")`: existing strict per-extension two independent Release/catalog/open-PR snapshots, now parameterized for all 14 allowlisted names **without changing the wal2json default** or its schedule.
- `catalog_fleet14_readonly.audit_fleet(api, expected_main_sha)`: assert exactly the `verified_release_record.ALLOWED` 14-name set, protected and exact triggering Catalog main SHA before and after, identical open Catalog PR identities at both ends, and for each name two independently fetched complete per-extension snapshots with strict nonpublishing output. There is **no atomic GitHub-wide snapshot**. A change during the per-extension pair, Catalog main movement or a changed PR inventory is DENY.
- The result is only `FLEET_METADATA_NO_CHANGE` or `FLEET_REQUIRES_INDEPENDENT_RELEASE_REVIEW`. Even observed newer public metadata or an existing record proposal is **not authorization to verify an attestation, create a PR, tag, merge or release**. Each result retains `verifiedSignedRelease=false`, `proposalAuthorized=false`, `mutationsEnabled=false` and `publishableReceipt=false`.
- `.github/workflows/catalog-fleet14-readonly-canary.yml` only runs on an exact **protected-main `push` touching that exact workflow file**. The token has `contents:read`, there is **no `schedule`, `workflow_dispatch`, event-triggered proposal or write**, and all actions are pinned. The existing wal2json 9:30 JST schedule is completely unaffected.

## Fail-closed acceptance

The existing GitHub REST GET allowlist rejects other repositories, unsafe endpoints, redirects, duplicates, oversized/partial JSON and pagination. `tests/test_catalog_fleet14_readonly.py` denies wrong protected main, missing/stale fleet items, duplicate/malformed open PR identity, TOCTOU main/PR changes, unsafe trigger, forged publishable output and wrong fleet count. Existing `tests/test_catalog_scheduled_readonly.py` continues to cover per-extension Release race and new-release/duplicate proposal classification.

The first actual one-shot main run is the only acceptable proof of API end-to-end metadata behavior; mocks are not an online receipt. If a repository has not-yet-cataloged Releases, malformed API state, or a changed public Release, the canary fails or reports review required without changing GitHub. The pilot makes no new independent ZIP/SBOM/Grype/Sigstore verification. Do not label `FLEET_METADATA_NO_CHANGE` a verified signed-release gate.

## Remaining

Once real one-shot acceptance and the existing wal2json **actual scheduled** run are both confirmed, a later separate protected PR may propose adopting a 14-name daily read-only schedule. Do not expand it automatically now. Keep Issue #75 OPEN and record run SHA, protected required `validate`, and per-extension statuses.
