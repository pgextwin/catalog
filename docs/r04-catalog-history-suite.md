# R04 catalog history-suite dependency audit

Audited before separation at main `f97d63f1a015480f0834cd89a834cfaace197769`.

No AGENTS.md exists in this clone. Normal command is `python -m unittest discover -s tests -v`; .NET workflow builds the solution then runs the offline contract executable.

- **Keep normal:** formal ledger v2–v5 readers and their tests. `distribution_p1_batch.py` imports/validates v5; v5 validates v4, v4 validates v3, v3 validates v2. `distribution_offline_major_inventory_v1.py` also validates v5. These are live read-only policy inputs, despite their dates. Do not retire or move their validation/tamper contracts.
- **Keep normal:** `test_distribution_p1_historical_fleet.py` and `test_distribution_p1_historical_source.py`. Batch imports these source/profile verifiers, pins and inventory. `distribution_p1_orafce_cross_attempt.py` also uses historical-fleet verification. The retired `issue112-p1-fleet-readonly.yml` ran the batch and these tests. Frozen evidence remains necessary to these readers.
- **History:** `test_distribution_p1_historical_source_ledger_v2.py` validates the sealed, completed source-v2 intake/artifact. Searches found no production reader/workflow consumer of its module or v2 ledger (only this test and the module's own CLI). Genesis source-v1 remains live and normal. Preserve all materials and hostile tests.
- **History:** v02/v021/v022 release contracts, archived v01/v02 public smoke policies and R7 publication contract read only `tests/fixtures/historical-workflows/` and old intent metadata. Their Actions entrypoints are already retired. R6 candidate/runtime/workflow tests instead target the live `cli-candidate.yml` / candidate reader and MUST stay normal. The R7 asset-set helper is still used by `cli-release.yml`; its current tests stay.
- **Split:** three sealed Git-tree snapshot tests in `test_distribution_p1_batch.py` are the only local historical Git-object consumer found in normal tests. Move those tests and their test-only helpers, leaving the batch's byte/signature/profile/tamper contracts normal.
- **Keep normal:** `test_retired_one_shot_cli_workflows.py` guards absence of retired publishers, plus existing nonauthorization tests throughout live P1 readers. Expand/clarify the normal nonauthorization boundary as needed; frozen fixture content assertions can move to history.
- No catalog PRE-G4 tests were found. Fixed IDs in live identity/admission/byte tests are not treated as obsolete merely because they are fixed.


## Suite separation

Normal CI continues `python -m unittest discover -s tests -v`. The
`tests/history/` directory deliberately has no `__init__.py`, so unittest does
not discover it recursively. Run it explicitly with:

```
python -m unittest discover -s tests/history -v
```

Moved intact: seven archived CLI publisher/smoke contract files, the completed
source-v2 ledger/artifact test file, and the completed fleet14 canary fixture
reader's tests. Three sealed Git-tree checks and their test-only helpers were
extracted from `test_distribution_p1_batch.py`; all remaining live batch tests
stay normal. Frozen canary/bilingual fixture assertions were extracted from the
normal retired-workflow guard. No evidence, fixture, reader or policy was deleted.
Normal `test_historical_evidence_authority.py` exercises the actual old ledger
readers and confirms they return no publication/distribution permission.

`catalog-history.yml` supplies a **separate, read-only history job**, on PR/main
changes to history tests, fixtures, evidence, readers (`scripts/**`, including
shared validators), policies/config/schema, docs, workflow wiring and Git byte
attributes; manual dispatch also runs it. Archived workflow files retain their
original bytes, including obsolete source-path references, as inert fixtures.
The P1 read-only audit workflow is retired. Its reader tests remain in the
normal suite.

## Checkout-depth decision

The CLI now obtains pgextwin builds through the signed feed. The fixed
bootstrap and its Git-object test have been removed, so the .NET OSGeo
job uses the default shallow checkout. Validate still fetches full history
for Python's offline inventory and ledger admission tests. The history and
signed-feed publishing workflows also use full history for their own
Git-object and admission checks.

### R04 findings before the CLI migration

**Keep `fetch-depth: 0` in normal validate.** After separating the Python Git-tree
checks, the normal `.NET synthetic contract tests (offline)` step still executes
`TrustedBootstrapTests.RunAsync`. That test calls `GitOriginal` -> `git show
<TrustedCatalogBootstrap.CatalogSnapshotCommit>:<path>` for every entry in the
pinned policy's `catalogDigests`. The live `--fixed` bootstrap's exact-byte,
embedded-policy SHA256, numeric-pin and tamper-rejection contracts rely on these
original bytes. Moving the complete test would move live byte-integrity coverage;
this phase leaves it normal. A future change could supply authenticated immutable
fixture bytes to these same tests without historical Git lookup, preserving all
those checks, before reducing checkout depth.

The remaining Python suite has no historical local Git-object reads. The other
normal Linux steps (`validate_public_get_pin.py`, landscape/catalog validation,
.NET build) do not read historical local Git trees. Their remote API/signature
checks remain unchanged. `TrustedBootstrapTests` is the specific blocker; a
separate history job alone does not make normal validate history-free.

## Current authorized roster

`VerifiedFleetRoster` now validates nonempty membership up to 128 names, sorted
and unique, with lowercase safe identifiers up to 64 characters. It no longer
requires the original fourteen names. Membership authority still comes from the
protected authenticated index or the independently Sigstore-verified feed, bound
to immutable Catalog bytes. The signed feed's exact count/index/record/package
and selected-major checks are unchanged.

The Python feed producer had the same historical-membership restriction; it and
the workflow minimum-count checks now agree with the consumer. Removed members
must also be removed from the authorized index and record inventory. Removing
only an index entry, adding an unregistered entry, or losing a selected package
still fails. No signature, fetched-byte, admission, or per-version license
verification was changed. Canonical/golden and hostile tamper tests remain.

## Local validation

Python 3.12.3 (`python3`; workflows pin Python 3.13), .NET SDK 11.0.100:

- `python3 -m unittest discover -s tests -v` — **1,045 passed**.
- `python3 -m unittest discover -s tests/history -v` — **40 passed**.
- `PATH=/home/hatch/.dotnet:$PATH dotnet build dotnet/PgExtWin.slnx --configuration Release --nologo` — passed, zero warnings/errors.
- `PATH=/home/hatch/.dotnet:$PATH dotnet run --project dotnet/tests/PgExtWin.Contract.Tests --configuration Release --no-build` — **544 local read-only contract checks passed**.
- Affected live P1 ledger/fleet/source/batch tests, retirement guard,
  nonauthorization boundary and feed-producer tests also passed individually.
- Changed workflow YAML parsed successfully; `git diff --check` passed.
